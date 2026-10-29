These files are generated. Do not edit them by hand; run

    python -m tools.make_examples

The two benign responses are fabricated and signed with a key derived from a
published seed (tools/keys.py), so the matching certificate can be committed
while the private key never exists on disk. Every xsw-*.xml file is produced by
this repository's own --generate mode from the benign response above it, which
is why the digest and signature values in them are unchanged: exclusive
canonicalisation of the referenced element does not depend on where that element
sits in the document, and that is precisely why wrapping works.

FOR AUTHORISED TESTING ONLY. The xsw-*.xml documents are attack payloads. Send
them only to systems you own or have written permission to test.
