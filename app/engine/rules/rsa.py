"""PY-CRYPTO-RSA: RSA usage in the Python ``cryptography`` library.

The rule reads syntax, never text. A construct is RSA only when the AST shows
it: an import that resolves to the RSA namespace, an RSA class named in an
annotation, or a local name assigned directly from an RSA constructor. A
receiver whose type cannot be established produces nothing, so ``key.sign(...)``
on an unknown object is never reported.
"""

import ast
from dataclasses import dataclass, field
from enum import StrEnum

from app.engine.engine import engine_versions
from app.engine.parser import ParsedFile, SymbolKind
from app.engine.rules.base import (
    AnalysisContext,
    CryptoOperation,
    EvidenceBasis,
    MatchConfidence,
    RuleMatch,
)

RULE_ID = "PY-CRYPTO-RSA"
ALGORITHM = "RSA"
PRIMITIVE = "RSA"
LIBRARY = "cryptography"

# The one public RSA namespace. Internal binding namespaces such as
# ``cryptography.hazmat.bindings._rust.openssl.rsa`` are deliberately not
# covered: they are implementation detail, not an API a project calls.
RSA_MODULE = "cryptography.hazmat.primitives.asymmetric.rsa"

# Module-level callables that are themselves a cryptographic operation. The
# key-material helpers in the same module (rsa_crt_iqmp and friends) are not
# operations and are left out.
MODULE_OPERATIONS: dict[str, CryptoOperation] = {
    "generate_private_key": CryptoOperation.KEY_GENERATION,
}


class KeyKind(StrEnum):
    """Which half of an RSA key pair a name holds."""

    PRIVATE = "PRIVATE"
    PUBLIC = "PUBLIC"


PRIVATE_CLASSES = frozenset({"RSAPrivateKey", "RSAPrivateKeyWithSerialization"})
PUBLIC_CLASSES = frozenset({"RSAPublicKey", "RSAPublicKeyWithSerialization"})

CANONICAL_CLASS = {KeyKind.PRIVATE: "RSAPrivateKey", KeyKind.PUBLIC: "RSAPublicKey"}

# Key methods, and the half of the key pair each one requires. A method called
# on the wrong half is not reported: the evidence contradicts itself.
METHOD_OPERATIONS: dict[str, tuple[CryptoOperation, KeyKind]] = {
    "sign": (CryptoOperation.SIGN, KeyKind.PRIVATE),
    "decrypt": (CryptoOperation.DECRYPT, KeyKind.PRIVATE),
    "verify": (CryptoOperation.VERIFY, KeyKind.PUBLIC),
    "encrypt": (CryptoOperation.ENCRYPT, KeyKind.PUBLIC),
}

# The one derivation the rule follows: a public key taken from an established
# private key.
DERIVING_METHOD = "public_key"

_Scope = str | None
_Key = tuple[_Scope, str]


@dataclass(frozen=True)
class _Binding:
    """An established local name and how it was established."""

    kind: KeyKind
    basis: EvidenceBasis
    confidence: MatchConfidence


@dataclass(frozen=True)
class _Established:
    """One assignment's outcome: a key kind and the evidence that gave it."""

    kind: KeyKind
    basis: EvidenceBasis


def _is_class_body(enclosing_function: _Scope, enclosing_class: str | None) -> bool:
    """True when a binding sits directly in a class body.

    A class attribute is not visible as a bare name inside the class's own
    methods, so such a binding must not enter any function scope. The class is
    the innermost enclosing definition when there is no enclosing function, or
    when the class is itself nested inside that function.
    """
    if enclosing_class is None:
        return False
    if enclosing_function is None:
        return True
    return enclosing_class.startswith(f"{enclosing_function}.")


def _class_kind(name: str) -> KeyKind | None:
    if name in PRIVATE_CLASSES:
        return KeyKind.PRIVATE
    if name in PUBLIC_CLASSES:
        return KeyKind.PUBLIC
    return None


def resolve_chain(file: ParsedFile, chain: tuple[str, ...]) -> str | None:
    """Resolve a dotted chain against the file's imports.

    The root is looked up in the import index and the rest of the chain is
    appended, so ``rsa.generate_private_key`` and the fully spelled
    ``cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key``
    resolve to the same path. A root that was never imported gives None.
    """
    if not chain:
        return None
    target = file.resolve(chain[0])
    if target is None:
        return None
    return ".".join((target, *chain[1:]))


def rsa_member(path: str | None) -> str | None:
    """Return what a resolved path names inside the RSA module, or None."""
    if path is None:
        return None
    prefix = f"{RSA_MODULE}."
    if not path.startswith(prefix):
        return None
    return path[len(prefix) :]


@dataclass
class _KeyIndex:
    """Which local names hold an RSA key, per scope, for one file.

    Lookup walks outwards through enclosing *function* scopes only. A class
    body is skipped, because its names are not visible as bare names inside
    its methods. A name bound locally by something the rule could not
    establish stops the walk, so an unannotated parameter never inherits a
    module-level binding of the same name.
    """

    bindings: dict[_Key, _Binding] = field(default_factory=dict)
    locally_bound: dict[_Scope, set[str]] = field(default_factory=dict)
    function_scopes: set[str] = field(default_factory=set)

    def lookup(self, scope: _Scope, name: str) -> _Binding | None:
        for level in self._scope_chain(scope):
            binding = self.bindings.get((level, name))
            if binding is not None:
                return binding
            if name in self.locally_bound.get(level, ()):
                return None
        return None

    def _scope_chain(self, scope: _Scope) -> list[_Scope]:
        chain: list[_Scope] = []
        current = scope
        while current:
            if current in self.function_scopes:
                chain.append(current)
            current = current.rsplit(".", 1)[0] if "." in current else None
        chain.append(None)
        return chain


def build_key_index(file: ParsedFile) -> _KeyIndex:
    """Index the names that provably hold an RSA key in one file."""
    index = _KeyIndex()
    _collect_scopes(file, index)
    _collect_annotations(file, index)
    _collect_assignments(file, index)
    return index


def _collect_scopes(file: ParsedFile, index: _KeyIndex) -> None:
    """Record function scopes and every name bound inside each of them."""
    for kind in (SymbolKind.FUNCTION, SymbolKind.ASYNC_FUNCTION):
        for symbol in file.symbols_of(kind):
            index.function_scopes.add(symbol.qualified_name)
            if isinstance(symbol.node, ast.FunctionDef | ast.AsyncFunctionDef):
                bound = index.locally_bound.setdefault(symbol.qualified_name, set())
                bound.update(_parameter_names(symbol.node.args))

    for reference in file.names:
        if reference.context.value in {"STORE", "DELETE"}:
            index.locally_bound.setdefault(reference.enclosing_function, set()).add(
                reference.name
            )


def _parameter_names(arguments: ast.arguments) -> set[str]:
    names = {
        argument.arg
        for group in (arguments.posonlyargs, arguments.args, arguments.kwonlyargs)
        for argument in group
    }
    for extra in (arguments.vararg, arguments.kwarg):
        if extra is not None:
            names.add(extra.arg)
    return names


def _collect_annotations(file: ParsedFile, index: _KeyIndex) -> None:
    """Bind names annotated with an RSA key class.

    Supports ``key: RSAPrivateKey`` and ``key: rsa.RSAPrivateKey``, on a
    parameter or on an annotated assignment. A class-level annotation is
    skipped: it declares an attribute, not a bare name. Two annotations that
    disagree about the same name cancel each other out.
    """
    found: dict[_Key, set[KeyKind]] = {}
    for annotation in file.annotations:
        if annotation.target is None or not annotation.target.isidentifier():
            continue
        if _is_class_body(annotation.enclosing_function, annotation.enclosing_class):
            continue
        if annotation.annotation_chain is None:
            continue
        member = rsa_member(resolve_chain(file, annotation.annotation_chain))
        kind = _class_kind(member) if member else None
        if kind is None:
            continue
        found.setdefault((annotation.enclosing_function, annotation.target), set()).add(kind)

    for key, kinds in found.items():
        if len(kinds) == 1:
            index.bindings[key] = _Binding(
                kind=kinds.pop(),
                basis=EvidenceBasis.CLASS_ANNOTATION,
                confidence=MatchConfidence.HIGH,
            )


def _collect_assignments(file: ParsedFile, index: _KeyIndex) -> None:
    """Bind names assigned directly from an RSA constructor.

    Three forms are supported, all purely local and all a single hop:

    * ``key = rsa.generate_private_key(...)`` binds a private key.
    * ``public = key.public_key()`` binds a public key, but only when ``key``
      is already established in the same scope chain.
    * ``alias = key`` carries an established binding to another name.

    The last two read only bindings established before them, never each other,
    so no chain of inferences can form.

    A name assigned anywhere in its scope from something the rule cannot
    establish is left unbound, so a name that is sometimes an RSA key and
    sometimes not is never claimed. An annotation, being stronger evidence,
    is not overridden here.
    """
    candidates = [
        (assignment, assignment.targets[0], assignment.enclosing_function)
        for assignment in file.assignments
        if len(assignment.targets) == 1
        and assignment.targets[0].isidentifier()
        and not _is_class_body(assignment.enclosing_function, assignment.enclosing_class)
    ]

    direct: dict[_Key, _Established | None] = {}
    for assignment, name, scope in candidates:
        _merge(direct, (scope, name), _constructed(file, assignment.value_call))

    combined = dict(direct)
    for assignment, name, scope in candidates:
        if _constructed(file, assignment.value_call) is not None:
            continue
        established = _derived(index, direct, scope, assignment) or _aliased(
            index, direct, scope, assignment
        )
        # Merged unconditionally: an assignment this round cannot establish
        # must still be able to erase a name the round established elsewhere.
        _merge(combined, (scope, name), established, replace_unknown=True)

    for key, established in combined.items():
        if established is None or key in index.bindings:
            continue
        index.bindings[key] = _Binding(
            kind=established.kind,
            basis=established.basis,
            confidence=MatchConfidence.MEDIUM,
        )


def _merge(
    table: dict[_Key, _Established | None],
    key: _Key,
    established: _Established | None,
    *,
    replace_unknown: bool = False,
) -> None:
    """Record an assignment's outcome, letting a disagreement erase the name."""
    if key not in table:
        table[key] = established
        return
    existing = table[key]
    if existing is not None and established is not None and existing.kind is established.kind:
        return
    if existing == established:
        return
    if replace_unknown and existing is None:
        table[key] = established
        return
    table[key] = None


def _constructed(file: ParsedFile, value_call: str | None) -> _Established | None:
    """Return the key produced by an RSA constructor call, if it is one."""
    if value_call is None:
        return None
    member = rsa_member(resolve_chain(file, tuple(value_call.split("."))))
    if member is None:
        return None
    if MODULE_OPERATIONS.get(member) is not CryptoOperation.KEY_GENERATION:
        return None
    return _Established(KeyKind.PRIVATE, EvidenceBasis.CONSTRUCTOR_ASSIGNMENT)


def _established_kind(
    index: _KeyIndex,
    direct: dict[_Key, _Established | None],
    scope: _Scope,
    name: str,
) -> KeyKind | None:
    """Return the kind already established for a name, or None."""
    binding = index.lookup(scope, name)
    if binding is not None:
        return binding.kind
    prior = direct.get((scope, name))
    return prior.kind if prior is not None else None


def _derived(
    index: _KeyIndex,
    direct: dict[_Key, _Established | None],
    scope: _Scope,
    assignment,
) -> _Established | None:
    """Return PUBLIC for ``established_private.public_key()``, else None."""
    value_call = assignment.value_call
    if value_call is None:
        return None
    parts = value_call.split(".")
    if len(parts) != 2 or parts[1] != DERIVING_METHOD:
        return None
    if _established_kind(index, direct, scope, parts[0]) is not KeyKind.PRIVATE:
        return None
    return _Established(KeyKind.PUBLIC, EvidenceBasis.CONSTRUCTOR_ASSIGNMENT)


def _aliased(
    index: _KeyIndex,
    direct: dict[_Key, _Established | None],
    scope: _Scope,
    assignment,
) -> _Established | None:
    """Return the kind of ``alias = established_name``, else None."""
    value = assignment.value_expression
    if value is None or not value.isidentifier():
        return None
    kind = _established_kind(index, direct, scope, value)
    if kind is None:
        return None
    return _Established(kind, EvidenceBasis.ESTABLISHED_ALIAS)


class RsaRule:
    """Recognises RSA usage from the ``cryptography`` library."""

    rule_id = RULE_ID

    @property
    def version(self) -> str:
        """The configured rule set version, stamped on every match."""
        return engine_versions().ruleset_version

    def evaluate(self, node: ast.AST, context: AnalysisContext) -> RuleMatch | None:
        """Return an RSA observation for a call node, or None."""
        call = context.call(node)
        if call is None or call.chain is None:
            return None

        return self._imported_api(call, context) or self._receiver_api(call, context)

    def _imported_api(self, call, context: AnalysisContext) -> RuleMatch | None:
        """Match a call whose callable resolves into the RSA module itself."""
        member = rsa_member(resolve_chain(context.file, call.chain))
        if member is None:
            return None

        operation = MODULE_OPERATIONS.get(member)
        if operation is not None:
            return self._match(
                call,
                api=f"rsa.{member}",
                operation=operation,
                confidence=MatchConfidence.HIGH,
                basis=EvidenceBasis.DIRECT_MODULE_API,
            )

        class_name, _, method = member.partition(".")
        kind = _class_kind(class_name)
        entry = METHOD_OPERATIONS.get(method)
        if kind is None or entry is None or entry[1] is not kind:
            return None
        return self._match(
            call,
            api=f"{class_name}.{method}",
            operation=entry[0],
            confidence=MatchConfidence.HIGH,
            basis=EvidenceBasis.CLASS_IMPORT,
        )

    def _receiver_api(self, call, context: AnalysisContext) -> RuleMatch | None:
        """Match a key method on a local name established as an RSA key."""
        if len(call.chain) != 2:
            return None
        entry = METHOD_OPERATIONS.get(call.chain[1])
        if entry is None:
            return None
        operation, required = entry

        index = self._index_for(context)
        binding = index.lookup(call.enclosing_function, call.chain[0])
        if binding is None or binding.kind is not required:
            return None

        return self._match(
            call,
            api=f"{CANONICAL_CLASS[binding.kind]}.{call.chain[1]}",
            operation=operation,
            confidence=binding.confidence,
            basis=binding.basis,
        )

    def _index_for(self, context: AnalysisContext) -> _KeyIndex:
        index = context.cache.get(self.rule_id)
        if index is None:
            index = build_key_index(context.file)
            context.cache[self.rule_id] = index
        return index

    def _match(
        self,
        call,
        *,
        api: str,
        operation: CryptoOperation,
        confidence: MatchConfidence,
        basis: EvidenceBasis,
    ) -> RuleMatch:
        return RuleMatch(
            rule_id=self.rule_id,
            ruleset_version=self.version,
            algorithm=ALGORITHM,
            primitive=PRIMITIVE,
            library=LIBRARY,
            api=api,
            operation=operation,
            file_path=call.path,
            location=call.location,
            confidence=confidence,
            evidence_basis=basis,
            enclosing_function=call.enclosing_function,
            enclosing_class=call.enclosing_class,
            node=call.node,
        )
