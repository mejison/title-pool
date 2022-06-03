const bcrypt = require('bcrypt');
require('dotenv').config();

const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const User = require('../models/user');

const register = (req, res, next) => {
	User.find({ email: req.body.email })
		.exec()
		.then((user) => {
			if (user.length >= 1) {
				res.status(409).json({
				message:"Email Exists"
				})
			} else {
				bcrypt.hash(req.body.password, 10, (err, hash) => {
					if (err) {
						return res.status(500).json({
							error: err,
						});
					} else {
						const user = new User({
							_id: new mongoose.Types.ObjectId(),
							email: req.body.email,
							password: hash,
              				name: req.body.name,
						});
						user
							.save()
							.then(async (result) => {
								await result
									.save()
									.then((result1) => {
										res.status(201).json({
											userDetails: {
												id: result._id,
												email: result.email,
												name: result.name,
											},
										})
									})
									.catch((err) => {
										res.status(400).json({
											message: err.toString()
										})
									});
							})
							.catch((err) => {
								res.status(500).json({
									message: err.toString()
								})
							});
					}
				});
			}
		})
		.catch((err) => {
			res.status(500).json({
				message: err.toString()
			})
    	});
}

const login = (req, res, next) => {
	User.find({ email: req.body.email })
		.exec()
		.then((user) => {
			if (user.length < 1) {
				return res.status(401).json({
					message: "Auth failed: Email not found probably",
				});
			}
			bcrypt.compare(req.body.password, user[0].password, (err, result) => {
				if (err) {
					return res.status(401).json({
						message: "Auth failed",
					});
				}

				if (result) {
					const token = jwt.sign(
						{
              				id: user[0]._id,
							email: user[0].email,
							name: user[0].name,
						},
						process.env.jwtSecret,
						{
							expiresIn: "1d",
						}
          			);

					return res.status(200).json({
						message: "Auth successful",
						user: {
							id: user[0]._id,
							name: user[0].name,
							email: user[0].email
						},
						token: token,
					});
				}

				res.status(401).json({
					message: "Auth failed",
				});
			});
		})
		.catch((err) => {
			res.status(500).json({
				error: err,
			});
		});
}

module.exports = {
    register,
    login,
}