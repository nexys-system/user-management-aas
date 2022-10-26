"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.token = exports.jwtSecret = exports.tokenValidity = void 0;
exports.tokenValidity = 60 * 10; // 10min
exports.jwtSecret = process.env.JWT_SECRET || "";
exports.token = process.env.NEXYS_USER_MANAGEMENT_TOKEN || "";
