# Revision History for `openid-connect`

## Version 0.2.0 (February 17, 2023)

  * Due to breaking changes in the `jose` package:

    - Versions before 0.10 are no longer supported

    - Orphan instances of `MonadRandom` were removed from `jose` so
      you may need to create your own `Monad` that implements
      `MonadRandom`

  * Tolerate non-standard client authentication methods in discovery
    documents via a new constructor (@ondrap)

  * Allow access to the ID token (JWT) so you can log out of a session
    (`authenticationSuccessWithJwt`) (@ondrap)

## Version 0.1.0 (March 25, 2020)

Initial release.

### Minor Releases

  * Version 0.1.2 (May 26, 2022)

    - Update dependencies to their latest versions (thanks to @maksbotan)

  * Version 0.1.1 (May 24, 2021)

    - Update dependencies to their latest versions (thanks to @maksbotan)
