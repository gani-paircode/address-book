const _isNumber = require('lodash/isNumber');

const getPhoneNumberValidationMessage = phoneNumberStr => {
    if (phoneNumberStr && phoneNumberStr.length === 10 && _isNumber( parseInt(phoneNumberStr))) {
        return '';
    }
    return 'Invalid phone number. It should be of 10 digits';
}

module.exports = {
    getPhoneNumberValidationMessage,
}