# wenceslas

[![Cargo Build & Test](https://github.com/brews/wenceslas/actions/workflows/rust.yml/badge.svg)](https://github.com/brews/wenceslas/actions/workflows/rust.yml)
[![codecov](https://codecov.io/github/brews/wenceslas/graph/badge.svg?token=NVQ9H272M5)](https://codecov.io/github/brews/wenceslas)
[![container](https://github.com/brews/wenceslas/actions/workflows/container.yml/badge.svg)](https://github.com/brews/wenceslas/actions/workflows/container.yml)

A small web service to verify user emails and passwords against stored Wordpress password hashes.


The server responds with a verified/unverified decision whenever an email and
raw password are POSTed to the `/verify` endpoint. The server loads a CSV file
holding emails and Wordpress-hashed passwords into memory on startup.

The server can only verify requests against hashes from newer Wordpress-flavored
bcrypt - the default in Wordpress 6.8 - and earlier Wordpress versions using
phpass. These hashes have a `$P$` or `$wp` prefix. The server will fail on
startup if the CSV file has hashes with unknown prefixes.

The CSV file must be UTF-8 encoded with a header and columns giving `user_email`
and `user_pass`. No duplicate user emails are allowed and will cause the server to fail on startup.

The server will also respond with user profiles to GET requests to `/users` with an email parameter.

> [!WARNING]
> This application does not have features to securely run alone in a production environment.

## Example

Generate a CSV file with user email addresses and hashed passwords in an example directory.

```shell
  EXAMPLE_DIR="./exampledata"
  DB_FILE="wp_db.csv"
  DB_PATH="${EXAMPLE_DIR}/${DB_FILE}"

  mkdir $EXAMPLE_DIR

  echo 'user_email,user_pass' > $DB_PATH
  echo 'johndoe@example.com,$wp$2y$10$gN3SQdbNc/cVlK7DylUiVumiuujud7lR0h5J4M2ZsNRMYOFbED16q' >> $DB_PATH
  echo 'janedoe@example.com,$P$BsSozX7pxy0bajB//ff34WOg4vN9OI/' >> $DB_PATH
```

Now start the server. Here, we're using the container.

```shell
  docker run --rm  -p 8000:8000 \
    -v "${EXAMPLE_DIR}:/data:ro" \
    -e CSV_PATH="/data/${DB_FILE}" \
    -e HOST="0.0.0.0" \
    -e PORT="8000" \
    -e RUST_LOG="TRACE" \
    wenceslas:dev
```

Send requests to the server like

```shell
  curl -X POST "http://localhost:8000/verify" \
    -H 'Content-Type: application/json' \
    --data-raw '{"email": "johndoe@example.com", "password": "Test123Now!"}'
```

and the server responds with

```shell
  {"verified":true}
```

A request with bad email or password like

```shell
  curl -X POST "http://localhost:8000/verify" \
    -H 'Content-Type: application/json' \
    --data-raw '{"email": "janedoe@example.com", "password": "Test123Now!"}'
```

gets the response

```shell
  {"verified":false}
```

Poorly formatted request bodies will get a (hopefully) descriptive error message and a 422 response status code.

You can set an optional API key when the server starts. The server will only allow POST requests with this key in the header of each request. For example, we can generate a length key like

```shell
  APIKEY=$(openssl rand -base64 40)
```

And pass the key to the server on startup like

```shell
  docker run --rm  -p 8000:8000 \
    -v "${EXAMPLE_DIR}:/data:ro" \
    -e CSV_PATH="/data/${DB_FILE}" \
    -e HOST="0.0.0.0" \
    -e PORT="8000" \
    -e RUST_LOG="TRACE" \
    -e APIKEY="${APIKEY}" \
    wenceslas:dev
```

And now requests need to include the key in the header of their requests like

```shell
  curl -X POST "http://localhost:8000/verify" \
    -H "x-apikey: ${APIKEY}" \
    -H 'Content-Type: application/json' \
    --data-raw '{"email": "johndoe@example.com", "password": "Test123Now!"}'
```

or the server will reply with "401 Unauthorized" response status.

Again, it's worth noting that using the API key feature does not secure network communication. Simply using the API key feature is not adequate security for running this in a production environment. 

You can also use the `/user` endpoint to get user profiles. For example

```shell
  curl -X GET "http://localhost:8000/users?email=johndoe%40example.com" \
    -H "x-apikey: ${APIKEY}" \
    -H 'Content-Type: application/json'
```

is a request for the profile to johndoe@example.com and gets the response

```
  [{"user_email":"johndoe@example.com","display_name":null,"first_name":null,"last_name":null,"nickname":null}]
```

The response contains `null`s because these fields are optional, and not columns in the input CSV.

The response is a 404 if no profile is found for the requested email.

## Installation

wenceslas is typically run from prebuilt container images.

### Building from source

To build this from source you will need the Git Version Control System and the Rust toolchain.

First clone the repository.

Compile and run from source

```shell
# Use --locked for deterministic builds.
cargo run --locked

# Use --release for optimized builds without debugging symbols
```

### Local container build

With docker istalled and configured for your system, run

```shell
  docker build -t wenceslas:dev .
```

to build a container image tagged `wenceslas:dev`.

## Configuration

Configurations are set through environment variables.

- *CSV_PATH*: Required. Path to CSV file with user email and Wordpress password hashes. Must have columns and header `user_email` and `user_pass`.
- *HOST*: Required. IPv4 or IPv6 address to listen for requests. E.g. "127.0.0.1" or "::1".
- *PORT*: Required. Port over which to listen for requests. E.g. "8000".
- *APIKEY*: Key to check for in request headers under the "x-apikey" field. No auth is used if this is not set.
- *RUST_LOG*: Logging level.

## Support

wenceslas is open-source software made available under the terms of either the MIT License or the Apache License 2.0, at your option.

