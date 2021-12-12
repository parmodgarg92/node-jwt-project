const mongoose = require("mongoose");

const GrocerySchema = new mongoose.Schema({
  text: { type: String, required: true },
  done: { type: mongoose.SchemaTypes.Boolean, required: true },
  user: { type: mongoose.SchemaTypes.ObjectId, ref: "user " },
});

const Item = mongoose.model("Item", GrocerySchema);

module.exports = Item;
