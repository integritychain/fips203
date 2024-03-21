import * as wasm from "wasm";

let wasmForm = document.getElementById("wasmForm");

wasmForm.addEventListener("submit", (e) => {
    e.preventDefault();

    let seed = document.getElementById("seed");
    let result = "";

    if (seed.value) {
        result = wasm.run(seed.value);
        seed.value = "";
        document.getElementById("wasm-canvas").innerHTML = result;
    } else {
        alert("Please enter a non-empty seed u64 decimal number");
    }
});