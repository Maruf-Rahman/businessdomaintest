var mongoose  = require('mongoose');
var moment    = require('moment');

var Schema = mongoose.Schema;
//Token Schema
var TokenSchema = new Schema({
  value:          { type: String },
  revoked:        { type: Boolean, default: true },
  user:           { type: Schema.Types.ObjectId, ref: 'User' },
  date_created:   { type: Date },
  last_modified:  { type: Date }
});

TokenSchema.pre('save', function preSaveMiddleware(next) {
  var token = this;

  // set date modifications
  var now = moment().toISOString();

  token.date_created = now;
  token.last_modified = now;

  next();

});

/**
 * Model Attributes to expose
 */
TokenSchema.statics.whitelist = {
  _id: 1,
  value: 1,
  revoked: 1,
  user: 1,
  date_created: 1
};


// Expose Token model
module.exports = mongoose.model('Token', TokenSchema);
