function isInt(value) {
    return !Number.isNaN(parseFloat(value));
}

module.exports = {
    isInt
};