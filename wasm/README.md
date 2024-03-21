This is a simple WASM demo for the FIPS 203 code.

1. One-off installation:

   ~~~
   $ cargo install wasm-pack
   $ sudo apt install npm
   ~~~

2. To run the demo:

   ~~~
   $ cd wasm    # this directory
   $ wasm-pack build
   $ cd www
   $ npm install
   $ npm run start
   ~~~

If the final step fails, try preceding it with: `$ export NODE_OPTIONS=--openssl-legacy-provider`.

While this simple demo will run as-is, it likely has security vulnerabilities within the npm
dependencies that requires `npm audit fix --force` to resolve.
