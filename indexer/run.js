const { runIndexOnce } = require("./walrusIndexer");
const { saveRow } = require("./store");

runIndexOnce(saveRow)
  .then(() => console.log("Index build completed"))
  .catch((err) => {
    console.error("Index error", err);
    process.exitCode = 1;
  });
