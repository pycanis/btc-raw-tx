import init, { create_raw_tx } from "../wa/pkg/raw_btc_tx.js";

init().then(() => {
  document.getElementById("loading")?.classList.add("hidden");
  document.getElementById("content")?.classList.remove("hidden");
});

document.getElementById("create_tx")?.addEventListener("click", async () => {
  const tx = create_raw_tx(
    [
      {
        tx_id: "", // from some mempool explorer
        vout: 0,
        private_key: "", // WIF or raw
      },
    ],
    [
      {
        amount: 5000,
        address: "",
      },
    ]
  );

  console.log(await tx);
});
