const Joi = require('@hapi/joi');

const registerValidation = (data) => {
  const schema = Joi.object({
    name: Joi.string().min(6).required(),
    phonenumber: Joi.string().min(10).required().regex(/^[0-9]{10}$/i),
    password: Joi.string().min(6).required(),
  });
  return schema.validate(data);
};
const loginValidation = (data) => {
  const schema = Joi.object({
    phonenumber: Joi.string().min(10).required().regex(/^[0-9]{10}$/i),
    password: Joi.string().min(6).required(),
    pushTokens: Joi.array(),
  });
  return schema.validate(data);
};

module.exports.registerValidation = registerValidation;
module.exports.loginValidation = loginValidation;
