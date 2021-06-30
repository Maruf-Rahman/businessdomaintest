var express   = require('express');
var EmailController = require('../controllers/content');
var accessControl  = require('../controllers/auth').accessControl;

var router  = express.Router();
router.get('/:id', EmailController.fetchOne);
router.get('/', EmailController.fetchAll);
router.post('/', accessControl(['admin', 'super_admin']), EmailController.create);
router.param('id', EmailController.validateEmail);
router.put('/:id', accessControl(['admin', 'super_admin','helper']), EmailController.update);
router.delete('/:id', accessControl(['admin', 'super_admin']), EmailController.deleteEmail);

// Expose User Router
module.exports = router;
