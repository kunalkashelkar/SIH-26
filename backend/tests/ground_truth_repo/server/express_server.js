const express = require('express');
const router = express.Router();

router.post('/api/express/checkout', (req, res) => {
    const { amount, currency } = req.body;
    res.json({ status: 'ok' });
});

router.get('/api/express/orders/:orderId', (req, res) => {
    const orderId = req.params.orderId;
    res.json({ orderId });
});

module.exports = router;
