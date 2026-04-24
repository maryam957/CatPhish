/**
 * report_repository.js — in-memory phishing-report store (demo)
 * SECURITY: In production replace with a real DB.
 * Reports are keyed by a CSPRNG-generated ID, never by sequential int.
 */
const crypto = require('crypto');

class ReportRepository {
  constructor() {
    this.reports = new Map(); // id -> report
  }
  async create(data) {
    const id = crypto.randomBytes(16).toString('hex');
    const report = { id, ...data, createdAt: new Date() };
    this.reports.set(id, report);
    return report;
  }
  async findAll() { return Array.from(this.reports.values()); }
  async findById(id) { return this.reports.get(id) || null; }
}
module.exports = ReportRepository;
