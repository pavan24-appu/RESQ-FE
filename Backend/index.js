/*
===========================================================
 DISASTER MANAGEMENT SYSTEM - UPGRADED BACKEND (backend.js)
===========================================================
Run: node backend.js
===========================================================
*/

require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const http = require("http");
const { Server } = require("socket.io");
const { z } = require("zod");
const asyncHandler = require("express-async-handler");
const rateLimit = require("express-rate-limit");

const app = express();
const server = http.createServer(app);

/* =========================================================
   CONFIGURATION
========================================================= */
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/disaster_management";

/* =========================================================
   SECURITY & MIDDLEWARE
========================================================= */
app.use(cors({ origin: process.env.CLIENT_URL || "*" }));
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan("dev"));

// Rate Limiting to prevent DDoS and spam
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: { success: false, message: "Too many requests from this IP, please try again after 15 minutes" }
});
app.use("/api/", apiLimiter);

/* =========================================================
   DATABASE CONNECTION
========================================================= */
mongoose
    .connect(process.env.MONGO_URI)
    .then(() => console.log("MongoDB connected successfully"))
    .catch((error) => console.error("MongoDB connection error:", error.message));

/* =========================================================
   SCHEMAS (MODELS)
========================================================= */

const incidentSchema = new mongoose.Schema({
    title: { type: String, required: true, trim: true },
    description: { type: String, default: "" },
    type: { type: String, enum: ["flood", "earthquake", "fire", "cyclone", "landslide", "tsunami", "industrial", "chemical", "biological", "other"], required: true },
    severity: { type: String, enum: ["low", "moderate", "high", "critical"], default: "moderate" },
    status: { type: String, enum: ["active", "contained", "resolved"], default: "active" },
    affectedPopulation: { type: Number, default: 0 },
    region: { type: String, default: "general" }, // Added for Geofenced Socket Rooms
    location: {
        type: { type: String, enum: ["Point"], default: "Point" },
        coordinates: { type: [Number], required: true }
    },
    reportedBy: { type: String, default: "System" }
}, { timestamps: true });
incidentSchema.index({ location: "2dsphere" });
const Incident = mongoose.model("Incident", incidentSchema);

const redZoneSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: { type: String, default: "" },
    riskLevel: { type: String, enum: ["red", "orange", "yellow"], default: "red" },
    disasterType: { type: String, default: "general" },
    affectedPopulation: { type: Number, default: 0 },
    evacuationRequired: { type: Boolean, default: false },
    region: { type: String, default: "general" },
    geometry: {
        type: { type: String, enum: ["Polygon", "MultiPolygon"], required: true },
        coordinates: { type: Array, required: true }
    }
}, { timestamps: true });
redZoneSchema.index({ geometry: "2dsphere" });
const RedZone = mongoose.model("RedZone", redZoneSchema);

const hospitalSchema = new mongoose.Schema({
    name: { type: String, required: true },
    type: { type: String, enum: ["hospital", "clinic", "medical_center", "trauma_center"], default: "hospital" },
    phone: { type: String, default: "" },
    emergency: { type: Boolean, default: true },
    bedsAvailable: { type: Number, default: 0 },
    address: { type: String, default: "" },
    location: {
        type: { type: String, enum: ["Point"], default: "Point" },
        coordinates: { type: [Number], required: true }
    }
}, { timestamps: true });
hospitalSchema.index({ location: "2dsphere" });
const Hospital = mongoose.model("Hospital", hospitalSchema);

const shelterSchema = new mongoose.Schema({
    name: { type: String, required: true },
    address: { type: String, default: "" },
    capacity: { type: Number, default: 0 },
    occupied: { type: Number, default: 0 },
    contact: { type: String, default: "" },
    status: { type: String, enum: ["open", "full", "closed"], default: "open" },
    location: {
        type: { type: String, enum: ["Point"], default: "Point" },
        coordinates: { type: [Number], required: true }
    }
}, { timestamps: true });
shelterSchema.index({ location: "2dsphere" });
const Shelter = mongoose.model("Shelter", shelterSchema);

const resourceSchema = new mongoose.Schema({
    name: { type: String, required: true },
    category: { type: String, enum: ["ambulance", "food", "water", "medicine", "rescue_equipment", "vehicle", "personnel", "other"], required: true },
    quantity: { type: Number, default: 0 },
    unit: { type: String, default: "units" },
    status: { type: String, enum: ["available", "limited", "unavailable"], default: "available" },
    location: {
        type: { type: String, enum: ["Point"], default: "Point" },
        coordinates: { type: [Number], required: true }
    }
}, { timestamps: true });
resourceSchema.index({ location: "2dsphere" });
const Resource = mongoose.model("Resource", resourceSchema);

/* =========================================================
   ZOD VALIDATION MIDDLEWARE
========================================================= */
const validateRequest = (schema) => (req, res, next) => {
    try {
        schema.parse(req.body);
        next();
    } catch (error) {
        return res.status(400).json({ success: false, message: "Validation error", errors: error.errors });
    }
};

const incidentValidationSchema = z.object({
    title: z.string().min(3, "Title must be at least 3 characters"),
    type: z.enum(["flood", "earthquake", "fire", "cyclone", "landslide", "tsunami", "industrial", "chemical", "biological", "other"]),
    severity: z.enum(["low", "moderate", "high", "critical"]).optional(),
    location: z.object({
        type: z.literal("Point").optional(),
        coordinates: z.array(z.number()).length(2, "Coordinates must have exactly [longitude, latitude]")
    }),
    region: z.string().optional()
}).passthrough(); // allows other fields like description

/* =========================================================
   ROUTES (WITH ASYNC HANDLER & PAGINATION)
========================================================= */

app.get("/api/health", (req, res) => {
    res.json({
        success: true,
        server: "online",
        database: mongoose.connection.readyState === 1 ? "connected" : "disconnected",
        timestamp: new Date()
    });
});

/* --- INCIDENTS --- */
app.get("/api/incidents", asyncHandler(async (req, res) => {
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 20;
    const skip = (page - 1) * limit;

    const incidents = await Incident.find().sort({ createdAt: -1 }).skip(skip).limit(limit);
    const total = await Incident.countDocuments();

    res.json({ success: true, count: incidents.length, total, page, totalPages: Math.ceil(total / limit), data: incidents });
}));

app.post("/api/incidents", validateRequest(incidentValidationSchema), asyncHandler(async (req, res) => {
    const incident = await Incident.create(req.body);
    
    // Geofenced Socket Emission
    const region = incident.region || "general";
    io.to(region).emit("newIncident", incident); // Alerts users in this region
    io.to("global").emit("newIncidentGlobal", incident); // Alerts dashboard admins

    res.status(201).json({ success: true, message: "Incident created", data: incident });
}));

/* --- RED ZONES --- */
app.get("/api/zones", asyncHandler(async (req, res) => {
    const zones = await RedZone.find();
    res.json({ success: true, count: zones.length, data: zones });
}));

app.post("/api/zones", asyncHandler(async (req, res) => {
    const zone = await RedZone.create(req.body);
    io.to(zone.region || "general").emit("zoneCreated", zone);
    res.status(201).json({ success: true, message: "Zone created", data: zone });
}));

/* --- GIS & GEOJSON --- */
app.get("/api/gis/zones", asyncHandler(async (req, res) => {
    const zones = await RedZone.find();
    res.json({
        type: "FeatureCollection",
        features: zones.map((zone) => ({
            type: "Feature",
            geometry: zone.geometry,
            properties: { id: zone._id, name: zone.name, riskLevel: zone.riskLevel, disasterType: zone.disasterType }
        }))
    });
}));

app.get("/api/gis/incidents", asyncHandler(async (req, res) => {
    const incidents = await Incident.find();
    res.json({
        type: "FeatureCollection",
        features: incidents.map((incident) => ({
            type: "Feature",
            geometry: incident.location,
            properties: { id: incident._id, title: incident.title, type: incident.type, severity: incident.severity }
        }))
    });
}));

/* --- EMERGENCY LOCATION SEARCH --- */
app.get("/api/emergency/location", asyncHandler(async (req, res) => {
    const lat = Number(req.query.lat);
    const lng = Number(req.query.lng);

    if (Number.isNaN(lat) || Number.isNaN(lng)) {
        return res.status(400).json({ success: false, message: "Valid latitude and longitude are required" });
    }

    const point = { type: "Point", coordinates: [lng, lat] };

    const [zones, hospitals, shelters, resources] = await Promise.all([
        RedZone.find({ geometry: { $geoIntersects: {$geometry: point } } }),
        Hospital.find({ location: { $near: {$geometry: point } } }).limit(5),
        Shelter.find({ status: { $ne: "closed" }, location: { $near: {$geometry: point } } }).limit(5),
        Resource.find({ status: { $ne: "unavailable" }, location: { $near: {$geometry: point } } }).limit(10)
    ]);

    res.json({
        success: true,
        location: { latitude: lat, longitude: lng },
        danger: { insideRedZone: zones.some((zone) => zone.riskLevel === "red"), zones },
        nearest: { hospitals, shelters, resources }
    });
}));

/* =========================================================
   SOCKET.IO (GEOFENCED REAL-TIME)
========================================================= */
const io = new Server(server, {
    cors: { origin: process.env.CLIENT_URL || "*", methods: ["GET", "POST", "PUT", "DELETE"] }
});

io.on("connection", (socket) => {
    console.log(`Client connected: ${socket.id}`);

    // Client requests to join a specific region for updates
    socket.on("joinRegion", (region) => {
        socket.join(region);
        console.log(`Socket ${socket.id} joined region: ${region}`);
        socket.emit("subscriptionStatus", { success: true, region });
    });
    
    // Admins joining a global room to see everything
    socket.on("joinGlobal", () => {
        socket.join("global");
    });

    socket.on("disconnect", () => console.log(`Client disconnected: ${socket.id}`));
});

/* =========================================================
   ERROR HANDLING (Must be last)
========================================================= */
app.use((req, res) => {
    res.status(404).json({ success: false, message: "API endpoint not found", path: req.originalUrl });
});

// Global Error Handler for asyncHandler and native errors
app.use((error, req, res, next) => {
    console.error(error);
    const statusCode = res.statusCode === 200 ? 500 : res.statusCode;
    res.status(statusCode).json({
        success: false,
        message: error.message || "Internal server error",
        stack: process.env.NODE_ENV === "production" ? null : error.stack // Hide stack trace in prod
    });
});

/* =========================================================
   START SERVER
========================================================= */
server.listen(PORT, () => {
    console.log(`\n==========================================`);
    console.log(` DISASTER MANAGEMENT SYSTEM `);
    console.log(`==========================================`);
    console.log(` Server: http://localhost:${PORT}`);
    console.log(` Health: http://localhost:${PORT}/api/health`);
    console.log(`==========================================\n`);
});