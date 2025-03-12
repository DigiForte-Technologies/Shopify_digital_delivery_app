const bcrypt = require('bcrypt');

const plainPassword = "2025";
const saltRounds = 10; // Recommended salt rounds

bcrypt.hash(plainPassword, saltRounds, (err, hash) => {
  if (err) {
    console.error("Error hashing password:", err);
  } else {
    console.log("Hashed password:", hash);
  }
});

