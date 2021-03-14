import express from 'express';
import { body, validationResult } from 'express-validator';
import xss from 'xss';

import { list, insert } from './db.js';

export const router = express.Router();

/**
 * Higher-order fall sem umlykur async middleware með villumeðhöndlun.
 *
 * @param {function} fn Middleware sem grípa á villur fyrir
 * @returns {function} Middleware með villumeðhöndlun
 */
function catchErrors(fn) {
  return (req, res, next) => fn(req, res, next).catch(next);
}

async function index(req, res) {
  const errors = [];
  const formData = {
    name: '',
    phone: '',
    comment: ''
  };

  const registrations = await list();

  res.render('index', {
    errors, formData, registrations,
  });
}

const phonePattern = '^[0-9]{3}-?[0-9]{4}$';

const validationMiddleware = [
  body('name')
    .isLength({ min: 1 })
    .withMessage('Nafn má ekki vera tómt'),
  body('name')
    .isLength({ max: 128 })
    .withMessage('Nafn má að hámarki vera 128 stafir'),
  body('phone')
    .isLength({ min: 1 })
    .withMessage('Símanúmer má ekki vera tómt'),
  body('phone')
    .matches(new RegExp(phonePattern))
    .withMessage('Símanúmer verður að vera á formi 000-0000 eða 0000000'),
    body('comment')
    .isLength({ max: 400 })
    .withMessage('Athugasemd má að hámarki vera 400 stafir'),
];

// Viljum keyra sér og með validation, ver gegn „self XSS“
const xssSanitizationMiddleware = [
  body('name').customSanitizer((v) => xss(v)),
  body('phone').customSanitizer((v) => xss(v)),
  body('comment').customSanitizer((v) => xss(v)),
];

const sanitizationMiddleware = [
  body('name').trim().escape(),
  body('phone').blacklist('-'),
];

async function validationCheck(req, res, next) {
  const {
    name, phone, comment,
  } = req.body;

  const formData = {
    name, phone, comment,
  };
  const registrations = await list();

  const validation = validationResult(req);

  if (!validation.isEmpty()) {
    return res.render('index', { formData, errors: validation.errors, registrations });
  }

  return next();
}

async function register(req, res) {
  const {
    name, phone, comment,
  } = req.body;

  let success = true;

  try {
    success = await insert({
      name, phone, comment,
    });
  } catch (e) {
    console.error(e);
  }

  if (success) {
    return res.redirect('/');
  }

  return res.render('error', { title: 'Gat ekki skráð!', text: 'Hafðir þú skrifað undir áður?' });
}

router.get('/', catchErrors(index));

router.post(
  '/',
  validationMiddleware,
  xssSanitizationMiddleware,
  catchErrors(validationCheck),
  sanitizationMiddleware,
  catchErrors(register),
);
