dmjwk
=====

dmjwk (pronounced "dumb jock") is a simple demo web server that provides a
basic [Resource Owner Password Credentials Grant] OAuth 2 flow that returns a
[JSON Web Tokens] for "authenticated" users. It signs the tokens with a
memory-persistent [JSON Web Key] set.


  [JSON Web Key]: https://www.rfc-editor.org/rfc/rfc7517
    "RFC 7517 JSON Web Key (JWK)"
  [JSON Web Tokens]: https://www.rfc-editor.org/rfc/rfc7519
    "RFC 7519 JSON Web Token (JWT)"
  [Resource Owner Password Credentials Grant]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.3
