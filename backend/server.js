require("dotenv").config();
const crypto = require("crypto");
const https = require("https");
const { db, auth } = require("./config/firebase");
const nodemailer = require("nodemailer");
const express = require("express");
const cors = require("cors");

const app = express();

// Call Firebase Auth REST API (works in all Node versions, no global fetch needed)
function firebaseSignInWithPassword(apiKey, email, password) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      email: email.trim(),
      password,
      returnSecureToken: true,
    });
    const url = new URL(`https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${apiKey}`);
    const req = https.request(
      {
        hostname: url.hostname,
        path: url.pathname + url.search,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => { data += chunk; });
        res.on("end", () => {
          try {
            const parsed = JSON.parse(data);
            if (res.statusCode >= 200 && res.statusCode < 300) resolve(parsed);
            else reject({ statusCode: res.statusCode, ...parsed });
          } catch (e) {
            reject(new Error(data || "Invalid response"));
          }
        });
      }
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

const VERIFICATION_TOKEN_EXPIRY_MS = 24 * 60 * 60 * 1000; // 24 hours
const emailTransporter = process.env.EMAIL_USER && process.env.EMAIL_PASS
  ? nodemailer.createTransport({
      service: process.env.EMAIL_SERVICE || "gmail",
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    })
  : null;

// Middleware
app.use(cors());
app.use(express.json());

// Test route
app.get("/", (req, res) => {
  res.send("VaxAlert API running...");
});

// Test Firestore connection
app.get("/test-firestore", async (req, res) => {
  try {
    const snapshot = await db.collection("test").get();
    res.json({ message: "Connected to Firestore!", count: snapshot.size });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Password validation (at least 8 characters, one number, one symbol)
function isPasswordValid(password) {
  if (!password || password.length < 8) return false;
  if (!/\d/.test(password)) return false;
  if (!/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password)) return false;
  return true;
}

// Register route
app.post("/api/auth/register", async (req, res) => {
  const { email, password, firstName, lastName, contactNumber } = req.body;

  // Validate input fields
  if (!email || !password || !firstName || !lastName || !contactNumber) {
    return res.status(400).json({ error: "All fields are required." });
  }

  if (!isPasswordValid(password)) {
    return res.status(400).json({
      error: "Password must be at least 8 characters and include one number and one symbol.",
    });
  }

  try {
    // Check if email already exists in Firebase Auth
    try {
      await auth.getUserByEmail(email);
      return res.status(400).json({ error: "This email is already registered." });
    } catch (e) {
      if (e.code !== "auth/user-not-found") throw e;
    }

    // Check if contact number already exists in Firestore
    const existingContact = await db.collection("users").where("contactNumber", "==", contactNumber.trim()).limit(1).get();
    if (!existingContact.empty) {
      return res.status(400).json({ error: "This contact number is already registered." });
    }

    // Create the user in Firebase Auth
    const userRecord = await auth.createUser({
      email: email.trim(),
      password,
      displayName: `${firstName.trim()} ${lastName.trim()}`,
    });

    const trimmedEmail = email.trim();

    // Save user details in Firestore (emailVerified updated when they click the link)
    await db.collection("users").doc(userRecord.uid).set({
      firstName: firstName.trim(),
      lastName: lastName.trim(),
      email: trimmedEmail,
      contactNumber: contactNumber.trim(),
      role: "parent",
      emailVerified: false,
    });

    // Create verification token in Firestore and send email
    const token = crypto.randomBytes(32).toString("hex");
    const baseUrl = process.env.API_BASE_URL || `http://localhost:${process.env.PORT || 5000}`;
    const verifyUrl = `${baseUrl}/api/auth/verify-email?token=${token}`;

    await db.collection("emailVerificationTokens").doc(token).set({
      userId: userRecord.uid,
      email: trimmedEmail,
      createdAt: Date.now(),
    });

    if (emailTransporter) {
      try {
        await emailTransporter.sendMail({
          from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
          to: trimmedEmail,
          subject: "Verify your VaxAlert email",
          html: `
            <p>Hi ${firstName.trim()},</p>
            <p>Please verify your email by clicking the link below:</p>
            <p><a href="${verifyUrl}">Verify my email</a></p>
            <p>This link expires in 24 hours.</p>
            <p>If you didn't create an account, you can ignore this email.</p>
            <p>— VaxAlert</p>
          `,
        });
      } catch (err) {
        console.error("Verification email failed:", err.message);
      }
    } else {
      console.warn("Email not configured. Verification link:", verifyUrl);
    }

    res.status(201).json({
      message: "User registered successfully. Please verify your email.",
      userId: userRecord.uid,
    });
  } catch (error) {
    const message = error.code === "auth/email-already-exists"
      ? "This email is already registered."
      : error.message;
    res.status(400).json({ error: message });
  }
});

// Verify email (Firestore): token stored in emailVerificationTokens, updates users.emailVerified
app.get("/api/auth/verify-email", async (req, res) => {
  const { token } = req.query;
  const loginUrl = process.env.LOGIN_PAGE_URL || "http://localhost:5500/frontend/login.html";

  if (!token) {
    return res.redirect(`${loginUrl}?error=missing-token`);
  }

  try {
    const tokenRef = db.collection("emailVerificationTokens").doc(token);
    const tokenSnap = await tokenRef.get();

    if (!tokenSnap.exists) {
      return res.redirect(`${loginUrl}?error=invalid-token`);
    }

    const data = tokenSnap.data();
    const createdAt = data.createdAt;
    if (Date.now() - createdAt > VERIFICATION_TOKEN_EXPIRY_MS) {
      await tokenRef.delete();
      return res.redirect(`${loginUrl}?error=token-expired`);
    }

    const { userId } = data;

    // Update Firestore user: emailVerified = true
    await db.collection("users").doc(userId).update({ emailVerified: true });

    // Optional: keep Firebase Auth in sync
    try {
      await auth.updateUser(userId, { emailVerified: true });
    } catch (_) {}

    await tokenRef.delete();

    return res.redirect(`${loginUrl}?verified=1`);
  } catch (error) {
    console.error("Verify email error:", error);
    return res.redirect(`${loginUrl}?error=verification-failed`);
  }
});

// Login route: verify password via Firebase REST, then check emailVerified in Firestore
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required." });
  }

  const apiKey = process.env.FIREBASE_WEB_API_KEY;
  if (!apiKey) {
    return res.status(503).json({ error: "Login is not configured. Set FIREBASE_WEB_API_KEY in .env" });
  }

  try {
    const data = await firebaseSignInWithPassword(apiKey, email, password);
    const uid = data.localId;

    const userDoc = await db.collection("users").doc(uid).get();
    if (!userDoc.exists) {
      return res.status(400).json({ error: "User profile not found." });
    }

    const emailVerified = userDoc.data().emailVerified === true;
    if (!emailVerified) {
      return res.status(403).json({ error: "Please verify your email first. Check your inbox for the verification link." });
    }

    return res.status(200).json({
      message: "Login successful!",
      userId: uid,
      email: data.email,
      idToken: data.idToken,
    });
  } catch (err) {
    // Firebase REST error shape: { error: { message: "..." } } or { error: { code, message } }
    const fbMsg = err.error?.message || err.message || "";
    const isInvalidCreds =
      fbMsg.includes("INVALID_LOGIN_CREDENTIALS") ||
      fbMsg.includes("EMAIL_NOT_FOUND") ||
      fbMsg.includes("INVALID_PASSWORD") ||
      err.statusCode === 401;

    if (isInvalidCreds) {
      return res.status(401).json({ error: "Invalid email or password." });
    }
    if (fbMsg.includes("API key")) {
      return res.status(503).json({
        error: "Server auth config error. Check FIREBASE_WEB_API_KEY and API key restrictions in Firebase Console.",
      });
    }

    console.error("Login error:", err);
    return res.status(500).json({
      error: err.error?.message || err.message || "Login failed.",
    });
  }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
