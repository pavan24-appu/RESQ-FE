/*
===========================================================
 RESQ DISASTER MANAGEMENT SYSTEM - BACKEND (backend.js)
 Run:        node backend.js
 First run:  node backend.js --seed   (adds sample data once)
===========================================================
*/
require("dotenv").config();

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const http = require("http");
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Server } = require("socket.io");
const { z } = require("zod");
const asyncHandler = require("express-async-handler");
const rateLimit = require("express-rate-limit");

const app = express();
const server = http.createServer(app);

/* ========================= CONFIG ========================= */
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/disaster_management";
const ORIGINS = process.env.CLIENT_URL ? process.env.CLIENT_URL.split(",").map((s) => s.trim()) : "*";
const CENTER = { lat: Number(process.env.CENTER_LAT) || 12.3, lng: Number(process.env.CENTER_LNG) || 76.65 };
const JWT_SECRET = process.env.JWT_SECRET || (console.warn("JWT_SECRET not set: using a temporary key (logins reset on restart)"), crypto.randomBytes(32).toString("hex"));
const UPLOADS = path.join(__dirname, "uploads");
fs.mkdirSync(UPLOADS, { recursive: true });

/* ======================= MIDDLEWARE ======================= */
app.set("trust proxy", 1);
app.use(cors({ origin: ORIGINS }));
app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } })); // lets the dashboard show uploaded photos
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan("dev"));
app.use("/uploads", express.static(UPLOADS));

const limiter = (windowMs, max, message) => rateLimit({ windowMs, max, message: { success: false, message } });
app.use("/api/", limiter(15 * 60 * 1000, 600, "Too many requests, please try again later"));
const authLimiter = limiter(15 * 60 * 1000, 20, "Too many sign-in attempts, try again later");
const reportLimiter = limiter(60 * 60 * 1000, 20, "Report limit reached, try again later");

/* ======================== DATABASE ======================== */
mongoose
    .connect(MONGODB_URI)
    .then(async () => {
        console.log("MongoDB connected successfully");
        if (process.argv.includes("--seed")) await seed();
    })
    .catch((e) => console.error("MongoDB connection error:", e.message));

/* ======================== MODELS ========================== */
const point = { type: { type: String, enum: ["Point"], default: "Point" }, coordinates: { type: [Number], required: true } };
const model = (name, def, idx) => {
    const s = new mongoose.Schema(def, { timestamps: true });
    if (idx) s.index(idx);
    return mongoose.model(name, s);
};

const Incident = model("Incident", {
    title: { type: String, required: true, trim: true },
    description: { type: String, default: "" },
    type: { type: String, enum: ["flood", "earthquake", "fire", "cyclone", "landslide", "tsunami", "industrial", "chemical", "biological", "other"], required: true },
    severity: { type: String, enum: ["low", "moderate", "high", "critical"], default: "moderate" },
    status: { type: String, enum: ["active", "contained", "resolved"], default: "active" },
    affectedPopulation: { type: Number, default: 0 },
    region: { type: String, default: "general" },
    location: point,
    reportedBy: { type: String, default: "System" }
}, { location: "2dsphere" });

const RedZone = model("RedZone", {
    name: { type: String, required: true },
    description: { type: String, default: "" },
    riskLevel: { type: String, enum: ["red", "orange", "yellow"], default: "red" },
    disasterType: { type: String, default: "general" },
    affectedPopulation: { type: Number, default: 0 },
    evacuationRequired: { type: Boolean, default: false },
    region: { type: String, default: "general" },
    geometry: { type: { type: String, enum: ["Polygon", "MultiPolygon"], required: true }, coordinates: { type: Array, required: true } }
}, { geometry: "2dsphere" });

const Hospital = model("Hospital", {
    name: { type: String, required: true },
    type: { type: String, enum: ["hospital", "clinic", "medical_center", "trauma_center"], default: "hospital" },
    phone: { type: String, default: "" },
    emergency: { type: Boolean, default: true },
    bedsAvailable: { type: Number, default: 0 },
    totalBeds: { type: Number, default: 0 },
    address: { type: String, default: "" },
    location: point
}, { location: "2dsphere" });

const Shelter = model("Shelter", {
    name: { type: String, required: true },
    type: { type: String, default: "Relief shelter" }, // e.g. Relief shelter, Bunker / fortified shelter
    address: { type: String, default: "" },
    capacity: { type: Number, default: 0 },
    occupied: { type: Number, default: 0 },
    contact: { type: String, default: "" },
    status: { type: String, enum: ["open", "full", "closed"], default: "open" },
    location: point
}, { location: "2dsphere" });

const Resource = model("Resource", {
    name: { type: String, required: true },
    category: { type: String, enum: ["ambulance", "food", "water", "medicine", "rescue_equipment", "vehicle", "personnel", "other"], required: true },
    quantity: { type: Number, default: 0 },          // currently available
    total: { type: Number, default: 0 },             // total capacity (0 = same as quantity)
    unit: { type: String, default: "units" },
    status: { type: String, enum: ["available", "limited", "unavailable"], default: "available" },
    location: point
}, { location: "2dsphere" });

const User = model("User", {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
    role: { type: String, enum: ["citizen", "admin"], default: "citizen" }
});

const Alert = model("Alert", {
    title: { type: String, required: true, trim: true },
    msg: { type: String, required: true, trim: true },
    sev: { type: String, enum: ["info", "warning", "critical"], default: "warning" },
    aud: { type: String, default: "All registered users" },
    by: { type: String, default: "Control room" }
});

const DamageReport = model("DamageReport", {
    type: { type: String, required: true, maxlength: 60 },
    note: { type: String, required: true, maxlength: 300 },
    photoUrl: { type: String, default: "" },
    location: point,
    status: { type: String, enum: ["pending", "verified", "rejected"], default: "pending" }
}, { location: "2dsphere" });

const Prediction = model("Prediction", { hazard: String, risk: Number }, { hazard: 1, createdAt: -1 });

/* ====================== AUTH HELPERS ====================== */
const sign = (u) => jwt.sign({ id: u._id, role: u.role, name: u.name }, JWT_SECRET, { expiresIn: "7d" });
const safeUser = (u) => ({ name: u.name, email: u.email, role: u.role });
const auth = (req, res, next) => {
    try {
        req.user = jwt.verify((req.headers.authorization || "").replace("Bearer ", ""), JWT_SECRET);
        next();
    } catch (e) {
        res.status(401).json({ success: false, message: "Please sign in" });
    }
};
const adminOnly = (req, res, next) => (req.user.role === "admin" ? next() : res.status(403).json({ success: false, message: "Admin access required" }));

/* ====================== VALIDATION ======================== */
const validate = (schema) => (req, res, next) => {
    const r = schema.safeParse(req.body);
    if (!r.success) return res.status(400).json({ success: false, message: "Validation error", errors: r.error.issues });
    req.body = r.data;
    next();
};
const coords = z.object({ type: z.literal("Point").optional(), coordinates: z.tuple([z.number().min(-180).max(180), z.number().min(-90).max(90)]) });
const incidentSchema = z.object({
    title: z.string().min(3).max(120),
    type: z.enum(["flood", "earthquake", "fire", "cyclone", "landslide", "tsunami", "industrial", "chemical", "biological", "other"]),
    severity: z.enum(["low", "moderate", "high", "critical"]).optional(),
    description: z.string().max(1000).optional(),
    region: z.string().max(60).optional(),
    location: coords
}).passthrough();
const zoneSchema = z.object({
    name: z.string().min(2), riskLevel: z.enum(["red", "orange", "yellow"]).optional(), disasterType: z.string().optional(),
    region: z.string().optional(), geometry: z.object({ type: z.enum(["Polygon", "MultiPolygon"]), coordinates: z.array(z.any()) })
}).passthrough();
const authSchema = z.object({ name: z.string().min(2).max(60).optional(), email: z.string().email(), password: z.string().min(6).max(100) });
const alertSchema = z.object({
    title: z.string().min(3).max(80), msg: z.string().min(3).max(300),
    sev: z.enum(["info", "warning", "critical"]).default("warning"), aud: z.string().max(60).optional()
});

/* ========================= SOCKET ========================= */
const io = new Server(server, { cors: { origin: ORIGINS, methods: ["GET", "POST"] } });
io.on("connection", (socket) => {
    socket.join("general"); // every dashboard receives general updates
    socket.on("joinRegion", (region) => {
        if (typeof region !== "string" || region.length > 60) return;
        socket.join(region);
        socket.emit("subscriptionStatus", { success: true, region });
    });
    socket.on("joinGlobal", () => socket.join("global"));
});

/* ========================== ROUTES ======================== */
app.get("/api/health", (req, res) =>
    res.json({ success: true, server: "online", database: mongoose.connection.readyState === 1 ? "connected" : "disconnected", timestamp: new Date() })
);

/* ---- Auth (dashboard sign in / register) ---- */
app.post("/api/auth/register", authLimiter, validate(authSchema), asyncHandler(async (req, res) => {
    const { name, email, password } = req.body;
    if (!name) return res.status(400).json({ success: false, message: "Name is required" });
    if (await User.findOne({ email })) return res.status(409).json({ success: false, message: "Email already registered" });
    const role = process.env.ADMIN_EMAIL && process.env.ADMIN_EMAIL.toLowerCase() === email.toLowerCase() ? "admin" : "citizen";
    const user = await User.create({ name, email, passwordHash: await bcrypt.hash(password, 10), role });
    res.status(201).json({ success: true, user: safeUser(user), token: sign(user) });
}));
app.post("/api/auth/login", authLimiter, validate(authSchema), asyncHandler(async (req, res) => {
    const user = await User.findOne({ email: req.body.email });
    if (!user || !(await bcrypt.compare(req.body.password, user.passwordHash)))
        return res.status(401).json({ success: false, message: "Wrong email or password" });
    res.json({ success: true, user: safeUser(user), token: sign(user) });
}));

/* ---- Incidents ---- */
app.get("/api/incidents", asyncHandler(async (req, res) => {
    const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 1), 100);
    const filter = req.query.status ? { status: String(req.query.status) } : {};
    const [data, total] = await Promise.all([
        Incident.find(filter).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit),
        Incident.countDocuments(filter)
    ]);
    res.json({ success: true, count: data.length, total, page, totalPages: Math.ceil(total / limit), data });
}));
app.post("/api/incidents", auth, adminOnly, validate(incidentSchema), asyncHandler(async (req, res) => {
    const incident = await Incident.create(req.body);
    io.to(incident.region || "general").to("general").emit("newIncident", incident); // dashboard toast + refresh
    io.to("global").emit("newIncidentGlobal", incident);
    res.status(201).json({ success: true, message: "Incident created", data: incident });
}));

/* ---- Red zones + GeoJSON for the map ---- */
app.get("/api/zones", asyncHandler(async (req, res) => {
    const data = await RedZone.find();
    res.json({ success: true, count: data.length, data });
}));
app.post("/api/zones", auth, adminOnly, validate(zoneSchema), asyncHandler(async (req, res) => {
    const zone = await RedZone.create(req.body);
    io.to(zone.region || "general").to("general").emit("zoneCreated", zone);
    res.status(201).json({ success: true, message: "Zone created", data: zone });
}));
app.get("/api/gis/zones", asyncHandler(async (req, res) => {
    const zones = await RedZone.find();
    res.json({
        type: "FeatureCollection",
        features: zones.map((z) => ({ type: "Feature", geometry: z.geometry, properties: { id: z._id, name: z.name, riskLevel: z.riskLevel, disasterType: z.disasterType } }))
    });
}));
app.get("/api/gis/incidents", asyncHandler(async (req, res) => {
    const list = await Incident.find({ status: "active" });
    res.json({
        type: "FeatureCollection",
        features: list.map((i) => ({ type: "Feature", geometry: i.location, properties: { id: i._id, title: i.title, type: i.type, severity: i.severity } }))
    });
}));

/* ---- SOS / nearest help (used by SOS button + Medical widget) ---- */
app.get("/api/emergency/location", asyncHandler(async (req, res) => {
    const lat = Number(req.query.lat), lng = Number(req.query.lng);
    if (!Number.isFinite(lat) || !Number.isFinite(lng) || Math.abs(lat) > 90 || Math.abs(lng) > 180)
        return res.status(400).json({ success: false, message: "Valid latitude and longitude are required" });
    const pt = { type: "Point", coordinates: [lng, lat] };
    const [zones, hospitals, shelters, resources] = await Promise.all([
        RedZone.find({ geometry: { $geoIntersects: { $geometry: pt } } }),
        Hospital.find({ location: { $near: { $geometry: pt } } }).limit(5),
        Shelter.find({ status: { $ne: "closed" }, location: { $near: { $geometry: pt } } }).limit(5),
        Resource.find({ status: { $ne: "unavailable" }, location: { $near: { $geometry: pt } } }).limit(10)
    ]);
    res.json({
        success: true,
        location: { latitude: lat, longitude: lng },
        danger: { insideRedZone: zones.some((z) => z.riskLevel === "red"), zones },
        nearest: { hospitals, shelters, resources }
    });
}));

/* ---- Shelters, bunkers and safe places (Evacuation panel) ---- */
app.get("/api/shelters", asyncHandler(async (req, res) => {
    const data = await Shelter.find({ status: { $ne: "closed" } });
    res.json({ success: true, count: data.length, data });
}));
app.post("/api/shelters", auth, adminOnly, asyncHandler(async (req, res) => {
    res.status(201).json({ success: true, data: await Shelter.create(req.body) });
}));
app.post("/api/hospitals", auth, adminOnly, asyncHandler(async (req, res) => {
    res.status(201).json({ success: true, data: await Hospital.create(req.body) });
}));

/* ---- Resource availability (food, water, ambulances, services) ---- */
const GROUP = { food: "Food & water", water: "Food & water", ambulance: "Ambulance & medical", medicine: "Ambulance & medical", rescue_equipment: "Rescue & safety", personnel: "Rescue & safety", vehicle: "Rescue & safety", other: "Shelter & other services" };
app.get("/api/resources", asyncHandler(async (req, res) => {
    const [items, beds, seats] = await Promise.all([
        Resource.find(),
        Hospital.aggregate([{ $group: { _id: null, a: { $sum: "$bedsAvailable" }, t: { $sum: "$totalBeds" } } }]),
        Shelter.aggregate([{ $match: { status: { $ne: "closed" } } }, { $group: { _id: null, c: { $sum: "$capacity" }, o: { $sum: "$occupied" } } }])
    ]);
    const data = items.map((r) => ({ id: r._id, cat: GROUP[r.category], name: r.name, available: r.quantity, total: Math.max(r.total || 0, r.quantity) || 1, unit: r.unit }));
    if (beds[0] && beds[0].t > 0) data.push({ cat: "Ambulance & medical", name: "Hospital beds", available: beds[0].a, total: beds[0].t });
    if (seats[0] && seats[0].c > 0) data.push({ cat: "Shelter & other services", name: "Shelter seats", available: Math.max(seats[0].c - seats[0].o, 0), total: seats[0].c });
    res.json({ success: true, count: data.length, data });
}));
app.post("/api/resources", auth, adminOnly, asyncHandler(async (req, res) => {
    res.status(201).json({ success: true, data: await Resource.create(req.body) });
}));
app.patch("/api/resources/:id", auth, adminOnly, asyncHandler(async (req, res) => {
    const r = await Resource.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true });
    r ? res.json({ success: true, data: r }) : res.status(404).json({ success: false, message: "Resource not found" });
}));

/* ---- AI risk predictions (rule-based model: live rain forecast + reported incidents) ---- */
const rainRisk = (mm) => (mm < 64.5 ? (mm / 64.5) * 60 : mm < 115.5 ? 60 + ((mm - 64.5) / 51) * 20 : Math.min(100, 80 + ((mm - 115.5) / 88.9) * 20)); // IMD heavy-rain bands
async function rain24h() {
    const r = await fetch(`https://api.open-meteo.com/v1/forecast?latitude=${CENTER.lat}&longitude=${CENTER.lng}&hourly=precipitation&forecast_hours=24`);
    const j = await r.json();
    return j.hourly.precipitation.reduce((a, b) => a + (b || 0), 0);
}
let predCache = { t: 0, data: null };
app.get("/api/predictions", asyncHandler(async (req, res) => {
    if (predCache.data && Date.now() - predCache.t < 10 * 60 * 1000) return res.json(predCache.data);
    let mm = 0, live = true;
    try { mm = await rain24h(); } catch (e) { live = false; }
    const active = await Incident.find({ status: "active" }, "type severity");
    const w = { low: 1, moderate: 2, high: 3, critical: 4 };
    const press = (type) => Math.min(40, active.filter((i) => i.type === type).reduce((a, i) => a + w[i.severity] * 8, 0));
    const rr = rainRisk(mm), src = live ? `${Math.round(mm)} mm rain forecast in 24 h` : "weather feed unavailable, based on reported incidents";
    const risks = [
        { hazard: "Flood", risk: Math.min(100, Math.round(rr * 0.6 + press("flood"))), note: `${src}; ${active.filter((i) => i.type === "flood").length} active flood incident(s)` },
        { hazard: "Heavy rainfall", risk: Math.round(rr), note: live ? `${Math.round(mm)} mm expected in the next 24 hours` : "Weather feed unavailable" },
        { hazard: "Landslide", risk: Math.min(100, Math.round(rr * 0.5 + press("landslide"))), note: `${src}; ${active.filter((i) => i.type === "landslide").length} active landslide incident(s)` }
    ];
    const now = Date.now();
    for (const r of risks) {
        const last = await Prediction.findOne({ hazard: r.hazard }).sort({ createdAt: -1 });
        if (!last || now - last.createdAt > 30 * 60 * 1000) await Prediction.create({ hazard: r.hazard, risk: r.risk });
        const old = await Prediction.findOne({ hazard: r.hazard, createdAt: { $lte: new Date(now - 18 * 3600e3), $gte: new Date(now - 36 * 3600e3) } }).sort({ createdAt: -1 });
        r.prev = old ? old.risk : null;
    }
    predCache = { t: now, data: { success: true, model: "rule-based", data: risks } };
    res.json(predCache.data);
}));

/* ---- Community alerts (broadcast to registered users) ---- */
const alertOut = (a) => ({ title: a.title, msg: a.msg, sev: a.sev, aud: a.aud, by: a.by, t: new Date(a.createdAt).getTime() });
app.get("/api/alerts", asyncHandler(async (req, res) => {
    res.json({ success: true, data: (await Alert.find().sort({ createdAt: -1 }).limit(20)).map(alertOut) });
}));
app.post("/api/alerts", auth, validate(alertSchema), asyncHandler(async (req, res) => {
    const a = await Alert.create({ ...req.body, by: req.user.name });
    io.emit("communityAlert", alertOut(a));
    res.status(201).json({ success: true, message: "Alert broadcast", data: alertOut(a) });
}));

/* ---- Crowdsourced damage reports (photo + pinned location) ---- */
const EXT = { "image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp", "image/gif": ".gif" };
const upload = multer({
    storage: multer.diskStorage({ destination: UPLOADS, filename: (q, f, cb) => cb(null, `${Date.now()}-${crypto.randomBytes(5).toString("hex")}${EXT[f.mimetype]}`) }),
    limits: { fileSize: 5 * 1024 * 1024, files: 1 },
    fileFilter: (q, f, cb) => (EXT[f.mimetype] ? cb(null, true) : cb(new Error("Only JPG, PNG, WEBP or GIF images are allowed")))
});
app.get("/api/damage-reports", asyncHandler(async (req, res) => {
    const data = await DamageReport.find({ status: { $ne: "rejected" } }).sort({ createdAt: -1 }).limit(100);
    res.json({ success: true, data });
}));
app.post("/api/damage-reports", reportLimiter, upload.single("photo"), asyncHandler(async (req, res) => {
    const lat = Number(req.body.lat), lng = Number(req.body.lng), type = String(req.body.type || "").trim(), note = String(req.body.note || "").trim();
    if (!Number.isFinite(lat) || !Number.isFinite(lng) || Math.abs(lat) > 90 || Math.abs(lng) > 180 || !type || !note) {
        if (req.file) fs.unlink(req.file.path, () => {});
        return res.status(400).json({ success: false, message: "Type, description and a valid pinned location are required" });
    }
    const report = await DamageReport.create({
        type: type.slice(0, 60), note: note.slice(0, 300), location: { type: "Point", coordinates: [lng, lat] },
        photoUrl: req.file ? `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}` : ""
    });
    io.to("global").emit("damageReport", report);
    res.status(201).json({ success: true, message: "Report received", data: report });
}));
app.patch("/api/damage-reports/:id", auth, adminOnly, asyncHandler(async (req, res) => {
    const r = await DamageReport.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true, runValidators: true });
    r ? res.json({ success: true, data: r }) : res.status(404).json({ success: false, message: "Report not found" });
}));

/* ======================== SAMPLE DATA ====================== */
async function seed() {
    const P = (lng, lat) => ({ type: "Point", coordinates: [lng, lat] });
    if (!(await Hospital.countDocuments())) {
        await Hospital.insertMany([
            { name: "Sample District Hospital, Mysuru", type: "trauma_center", phone: "0821-0000001", bedsAvailable: 60, totalBeds: 100, location: P(76.6552, 12.3052) },
            { name: "Sample General Hospital, Mandya", bedsAvailable: 35, totalBeds: 60, location: P(76.8951, 12.5218) },
            { name: "Sample Taluk Hospital, Madikeri", bedsAvailable: 25, totalBeds: 40, location: P(75.7382, 12.4244) }
        ]);
    }
    if (!(await Shelter.countDocuments())) {
        await Shelter.insertMany([
            { name: "Mysuru District Relief Camp", type: "Relief shelter", capacity: 1200, occupied: 850, location: P(76.6394, 12.2958) },
            { name: "Madikeri Fortified Shelter", type: "Bunker / fortified shelter", capacity: 400, occupied: 120, location: P(75.7382, 12.4244) },
            { name: "Mandya Government School Shelter", type: "School shelter", capacity: 600, occupied: 200, location: P(76.8951, 12.5218) },
            { name: "Hassan High-ground Camp", type: "Elevated safe ground", capacity: 900, occupied: 300, location: P(76.0996, 13.0068) },
            { name: "Chamarajanagar Community Hall", type: "Community shelter", capacity: 350, occupied: 90, location: P(76.9437, 11.9261) }
        ]);
    }
    if (!(await Resource.countDocuments())) {
        const L = P(76.6394, 12.2958);
        const R = (name, category, quantity, total, unit) => ({ name, category, quantity, total, unit, location: L });
        await Resource.insertMany([
            R("Drinking water (litres)", "water", 45000, 80000, "litres"), R("Packaged food kits", "food", 900, 2000, "kits"), R("Cooked meals per day", "food", 3500, 6000, "meals"),
            R("Ambulances (108)", "ambulance", 14, 25, "vehicles"), R("ICU beds", "medicine", 12, 30, "beds"), R("Oxygen cylinders", "medicine", 80, 150, "cylinders"),
            R("Rescue boats", "rescue_equipment", 6, 15, "boats"), R("NDRF / SDRF teams", "personnel", 4, 8, "teams"), R("Life jackets", "rescue_equipment", 300, 500, "pieces"),
            R("Generators", "other", 18, 40, "units"), R("Blankets and tents", "other", 420, 900, "pieces"), R("Fuel (litres)", "other", 5000, 12000, "litres")
        ]);
    }
    if (!(await RedZone.countDocuments())) {
        await RedZone.create({
            name: "Sample low-lying flood zone", riskLevel: "red", disasterType: "flood", evacuationRequired: true,
            geometry: { type: "Polygon", coordinates: [[[76.55, 12.25], [76.62, 12.25], [76.62, 12.31], [76.55, 12.31], [76.55, 12.25]]] }
        });
    }
    if (!(await Incident.countDocuments())) {
        await Incident.insertMany([
            { title: "River overflow near Mysuru", type: "flood", severity: "critical", location: P(76.58, 12.28) },
            { title: "Slope slip on Madikeri road", type: "landslide", severity: "high", location: P(75.75, 12.42) },
            { title: "Waterlogging in Mandya town", type: "flood", severity: "moderate", location: P(76.9, 12.52) }
        ]);
    }
    console.log("Sample data added (only to empty collections).");
}

/* ======================== ERRORS ========================== */
app.use((req, res) => res.status(404).json({ success: false, message: "API endpoint not found", path: req.originalUrl }));
app.use((err, req, res, next) => {
    const code = err instanceof multer.MulterError ? 400 : res.statusCode === 200 ? 500 : res.statusCode;
    if (code === 500) console.error(err);
    res.status(code).json({ success: false, message: err.message || "Internal server error", stack: process.env.NODE_ENV === "production" ? undefined : err.stack });
});

/* ========================= START ========================== */
server.listen(PORT, () => {
    console.log(`\n RESQ backend running: http://localhost:${PORT}`);
    console.log(` Health check:         http://localhost:${PORT}/api/health\n`);
});
