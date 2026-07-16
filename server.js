#!/usr/bin/env node

/**
 * Yahoo Mail MCP Server with OAuth2 - A beginner-friendly introduction to MCP
 * This server provides read-only access to Yahoo Mail via OAuth2 and IMAP
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import Imap from 'imap';
import { simpleParser } from 'mailparser';
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';
import nodemailer from 'nodemailer';
import MailComposer from 'nodemailer/lib/mail-composer/index.js';
import { createDAVClient } from 'tsdav';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// Load environment variables from .env file (for local development)
dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Persists OAuth authorization codes and access tokens to a JSON file so they
 * survive process restarts, and enforces real expiration instead of tokens
 * living forever. Replaces the previous in-memory Set/Map, which lost every
 * token on restart and never actually expired anything.
 *
 * Note: on hosts with an ephemeral filesystem (e.g. Render without an
 * attached persistent disk), this file is wiped on redeploy, not on a plain
 * process restart/sleep-wake — so re-auth is still occasionally required.
 */
class TokenStore {
    constructor(filePath) {
        this.filePath = filePath;
        this.data = { tokens: {}, codes: {} };
        this.load();
    }

    load() {
        try {
            fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
            if (fs.existsSync(this.filePath)) {
                const parsed = JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
                this.data.tokens = parsed.tokens || {};
                this.data.codes = parsed.codes || {};
            }
        } catch (e) {
            console.error('[TokenStore] Failed to load persisted store, starting fresh:', e.message);
        }
    }

    persist() {
        const tmpPath = `${this.filePath}.tmp`;
        fs.writeFileSync(tmpPath, JSON.stringify(this.data), 'utf8');
        fs.renameSync(tmpPath, this.filePath);
    }

    setAuthCode(code, authData, ttlMs = 60_000) {
        this.data.codes[code] = { ...authData, expiresAt: Date.now() + ttlMs };
        this.persist();
    }

    hasAuthCode(code) {
        const entry = this.data.codes[code];
        return !!entry && entry.expiresAt >= Date.now();
    }

    getAuthCode(code) {
        const entry = this.data.codes[code];
        if (!entry || entry.expiresAt < Date.now()) return null;
        return entry;
    }

    consumeAuthCode(code) {
        const entry = this.getAuthCode(code);
        delete this.data.codes[code];
        this.persist();
        return entry;
    }

    addToken(token, ttlMs = 3600_000, scope = 'mcp') {
        this.data.tokens[token] = { expiresAt: Date.now() + ttlMs, scope };
        this.persist();
    }

    isValidToken(token) {
        const entry = this.data.tokens[token];
        if (!entry) return false;
        if (entry.expiresAt < Date.now()) {
            delete this.data.tokens[token];
            this.persist();
            return false;
        }
        return true;
    }

    cleanupExpired() {
        const now = Date.now();
        let changed = false;
        for (const [k, v] of Object.entries(this.data.tokens)) {
            if (v.expiresAt < now) { delete this.data.tokens[k]; changed = true; }
        }
        for (const [k, v] of Object.entries(this.data.codes)) {
            if (v.expiresAt < now) { delete this.data.codes[k]; changed = true; }
        }
        if (changed) this.persist();
    }
}

/**
 * Exact-match redirect_uri / origin allowlisting. The previous implementation
 * used `redirect_uri.includes('claude.ai')`, which a URL like
 * `https://claude.ai.attacker.com` also satisfies. This checks the parsed
 * hostname exactly against an allowlist instead.
 */
const ALLOWED_REDIRECT_HOSTS = (process.env.ALLOWED_REDIRECT_HOSTS || 'claude.ai,claude.com')
    .split(',').map(h => h.trim()).filter(Boolean);

function isAllowedRedirectUri(uri) {
    let parsed;
    try {
        parsed = new URL(uri);
    } catch {
        return false;
    }
    if (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1') {
        return true; // local testing only
    }
    if (parsed.protocol !== 'https:') return false;
    return ALLOWED_REDIRECT_HOSTS.includes(parsed.hostname);
}

class YahooMailMCPServer {
    constructor() {
        this.server = new Server(
            {
                name: 'yahoo-mail-mcp',
                version: '3.0.0',
            },
            {
                capabilities: {
                    tools: {},
                },
            }
        );

        // Store active SSE transports (for routing messages)
        this.transports = new Map();

        // Persisted OAuth token/code store (see TokenStore above)
        this.tokenStore = new TokenStore(process.env.TOKEN_STORE_PATH || path.join(__dirname, 'data', 'tokens.json'));
        setInterval(() => this.tokenStore.cleanupExpired(), 5 * 60 * 1000).unref();

        this.setupToolHandlers();
        this.setupErrorHandling();
    }

    /**
     * Setup MCP tool handlers
     */
    setupToolHandlers() {
        // Handle tool listing
        this.server.setRequestHandler(ListToolsRequestSchema, async () => {
            return {
                tools: [
                    {
                        name: 'list_emails',
                        description: 'List recent emails from a Yahoo Mail folder. Returns UIDs (permanent identifiers) and enriched metadata including size, flags, and attachment status.',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                count: {
                                    type: 'number',
                                    description: 'Number of emails to retrieve (default: 10, max: 50)',
                                    default: 10
                                },
                                folder: {
                                    type: 'string',
                                    description: 'Folder to list emails from (default: INBOX). Use list_folders to see available folders.',
                                    default: 'INBOX'
                                },
                                offset: {
                                    type: 'number',
                                    description: 'Number of emails to skip (for pagination, default: 0)',
                                    default: 0
                                }
                            }
                        }
                    },
                    {
                        name: 'read_email',
                        description: 'Read email content using UIDs (permanent identifiers). UIDs don\'t change when emails are deleted. Get UIDs from list_emails or search_emails.',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                uids: {
                                    type: 'array',
                                    items: { type: 'number' },
                                    description: 'Array of UIDs to read. UIDs are permanent identifiers from list_emails.',
                                    minItems: 1
                                },
                                folder: {
                                    type: 'string',
                                    description: 'Folder containing the emails (default: INBOX)',
                                    default: 'INBOX'
                                }
                            },
                            required: ['uids']
                        }
                    },
                    {
                        name: 'search_emails',
                        description: 'Search emails using UIDs with advanced filters. Returns UIDs which are permanent identifiers that don\'t change when emails are deleted. Get UIDs from results for subsequent operations.',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                query: {
                                    type: 'string',
                                    description: 'Search term for subject or sender (can be empty for date-only searches)',
                                    default: ''
                                },
                                count: {
                                    type: 'number',
                                    description: 'Number of results to return (default: 10, max: 50)',
                                    default: 10
                                },
                                offset: {
                                    type: 'number',
                                    description: 'Number of matching (newest-first) results to skip, for pagination (default: 0)',
                                    default: 0
                                },
                                dateFrom: {
                                    type: 'string',
                                    description: 'Filter emails from this date onwards (ISO 8601 or RFC 2822 format)',
                                    default: null
                                },
                                dateTo: {
                                    type: 'string',
                                    description: 'Filter emails up to this date (ISO 8601 or RFC 2822 format)',
                                    default: null
                                },
                                sender: {
                                    type: 'string',
                                    description: 'Filter by specific sender email address or name',
                                    default: null
                                },
                                unreadOnly: {
                                    type: 'boolean',
                                    description: 'Only return unread emails (default: false)',
                                    default: false
                                },
                                flaggedOnly: {
                                    type: 'boolean',
                                    description: 'Only return flagged/starred emails (default: false)',
                                    default: false
                                },
                                folder: {
                                    type: 'string',
                                    description: 'Folder to search in (default: INBOX). Use list_folders to see available folders.',
                                    default: 'INBOX'
                                }
                            },
                            required: []
                        }
                    },
                    {
                        name: 'delete_emails',
                        description: 'Move emails to Trash folder using UIDs (soft delete, recoverable). UIDs are permanent identifiers.',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                uids: {
                                    type: 'array',
                                    items: { type: 'number' },
                                    description: 'Array of UIDs to delete',
                                    minItems: 1
                                },
                                folder: {
                                    type: 'string',
                                    description: 'Source folder (default: INBOX)',
                                    default: 'INBOX'
                                }
                            },
                            required: ['uids']
                        }
                    },
                    {
                        name: 'archive_emails',
                        description: 'Move emails to Archive folder using UIDs for long-term storage. UIDs are permanent identifiers.',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                uids: {
                                    type: 'array',
                                    items: { type: 'number' },
                                    description: 'Array of UIDs to archive',
                                    minItems: 1
                                },
                                folder: {
                                    type: 'string',
                                    description: 'Source folder (default: INBOX)',
                                    default: 'INBOX'
                                }
                            },
                            required: ['uids']
                        }
                    },
                    {
                        name: 'mark_as_read',
                        description: 'Mark emails as read using UIDs. UIDs are permanent identifiers.',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                uids: {
                                    type: 'array',
                                    items: { type: 'number' },
                                    description: 'Array of UIDs to mark as read',
                                    minItems: 1
                                },
                                folder: {
                                    type: 'string',
                                    description: 'Folder containing emails (default: INBOX)',
                                    default: 'INBOX'
                                }
                            },
                            required: ['uids']
                        }
                    },
                    {
                        name: 'mark_as_unread',
                        description: 'Mark emails as unread using UIDs. UIDs are permanent identifiers.',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                uids: {
                                    type: 'array',
                                    items: { type: 'number' },
                                    description: 'Array of UIDs to mark as unread',
                                    minItems: 1
                                },
                                folder: {
                                    type: 'string',
                                    description: 'Folder containing emails (default: INBOX)',
                                    default: 'INBOX'
                                }
                            },
                            required: ['uids']
                        }
                    },
                    {
                        name: 'flag_emails',
                        description: 'Flag emails as important/starred using UIDs. UIDs are permanent identifiers.',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                uids: {
                                    type: 'array',
                                    items: { type: 'number' },
                                    description: 'Array of UIDs to flag',
                                    minItems: 1
                                },
                                folder: {
                                    type: 'string',
                                    description: 'Folder containing emails (default: INBOX)',
                                    default: 'INBOX'
                                }
                            },
                            required: ['uids']
                        }
                    },
                    {
                        name: 'unflag_emails',
                        description: 'Remove flag/star from emails using UIDs. UIDs are permanent identifiers.',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                uids: {
                                    type: 'array',
                                    items: { type: 'number' },
                                    description: 'Array of UIDs to unflag',
                                    minItems: 1
                                },
                                folder: {
                                    type: 'string',
                                    description: 'Folder containing emails (default: INBOX)',
                                    default: 'INBOX'
                                }
                            },
                            required: ['uids']
                        }
                    },
                    {
                        name: 'move_emails',
                        description: 'Move emails to a specified folder using UIDs. UIDs are permanent identifiers. Use list_folders to see available folders.',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                uids: {
                                    type: 'array',
                                    items: { type: 'number' },
                                    description: 'Array of UIDs to move',
                                    minItems: 1
                                },
                                folderName: {
                                    type: 'string',
                                    description: 'Name of the destination folder (e.g., "Work", "Personal"). Use list_folders to see available folders.'
                                },
                                sourceFolder: {
                                    type: 'string',
                                    description: 'Source folder containing the emails (default: INBOX)',
                                    default: 'INBOX'
                                }
                            },
                            required: ['uids', 'folderName']
                        }
                    },
                    {
                        name: 'list_folders',
                        description: 'List all available IMAP folders/mailboxes in your Yahoo Mail account',
                        inputSchema: {
                            type: 'object',
                            properties: {}
                        }
                    },
                    {
                        name: 'create_draft',
                        description: 'Save a new email as a draft in your Yahoo Drafts folder (does not send it). Useful for drafting a reply or new message for the user to review and send themselves later.',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                to: { type: 'string', description: 'Recipient email address(es), comma-separated' },
                                cc: { type: 'string', description: 'CC email address(es), comma-separated', default: '' },
                                subject: { type: 'string', description: 'Email subject' },
                                text: { type: 'string', description: 'Plain-text body of the email' },
                                inReplyToUid: {
                                    type: 'number',
                                    description: 'UID of the email this drafts replies to, if any. Used to set threading headers and to prefix the subject with "Re:" if not already present.'
                                },
                                inReplyToFolder: {
                                    type: 'string',
                                    description: 'Folder containing the email referenced by inReplyToUid (default: INBOX)',
                                    default: 'INBOX'
                                }
                            },
                            required: ['to', 'subject', 'text']
                        }
                    },
                    {
                        name: 'send_email',
                        description: 'Send an email immediately via Yahoo SMTP. This actually sends the message — use create_draft instead if the user wants to review before sending. A copy is saved to the Sent folder.',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                to: { type: 'string', description: 'Recipient email address(es), comma-separated' },
                                cc: { type: 'string', description: 'CC email address(es), comma-separated', default: '' },
                                bcc: { type: 'string', description: 'BCC email address(es), comma-separated', default: '' },
                                subject: { type: 'string', description: 'Email subject' },
                                text: { type: 'string', description: 'Plain-text body of the email' },
                                inReplyToUid: {
                                    type: 'number',
                                    description: 'UID of the email this is replying to, if any. Used to set threading headers and to prefix the subject with "Re:" if not already present.'
                                },
                                inReplyToFolder: {
                                    type: 'string',
                                    description: 'Folder containing the email referenced by inReplyToUid (default: INBOX)',
                                    default: 'INBOX'
                                }
                            },
                            required: ['to', 'subject', 'text']
                        }
                    },
                    {
                        name: 'create_calendar_event',
                        description: 'Create an event on Yahoo Calendar via CalDAV.',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                title: { type: 'string', description: 'Event title/summary' },
                                start: { type: 'string', description: 'Start time, ISO 8601 (e.g. 2026-07-20T15:00:00-04:00)' },
                                end: { type: 'string', description: 'End time, ISO 8601. If omitted, defaults to 30 minutes after start.' },
                                description: { type: 'string', description: 'Event notes/description', default: '' },
                                location: { type: 'string', description: 'Event location', default: '' }
                            },
                            required: ['title', 'start']
                        }
                    },
                    {
                        name: 'get_daily_briefing',
                        description: 'One-call daily briefing: counts and lists unread mail, flagged/starred mail, and mail received today from INBOX. Use this first thing when the user asks "what\'s in my inbox" or wants a morning summary.',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                unreadLimit: { type: 'number', description: 'Max unread emails to include (default 15)', default: 15 },
                                flaggedLimit: { type: 'number', description: 'Max flagged emails to include (default 10)', default: 10 }
                            }
                        }
                    },
                    {
                        name: 'get_attachment',
                        description: 'List or retrieve attachments on a specific email by UID. Call without filename/attachmentIndex first to see what attachments exist and their sizes, then call again with one of those to retrieve it as base64. Large attachments are rejected (see MAX_ATTACHMENT_BYTES) rather than blowing up the response.',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                uid: { type: 'number', description: 'UID of the email (from list_emails/search_emails/read_email)' },
                                folder: { type: 'string', description: 'Folder containing the email (default: INBOX)', default: 'INBOX' },
                                filename: { type: 'string', description: 'Exact attachment filename to retrieve (see the listing from a filename-less call)' },
                                attachmentIndex: { type: 'number', description: 'Index of the attachment to retrieve, as an alternative to filename' }
                            },
                            required: ['uid']
                        }
                    }
                ]
            };
        });

        // Handle tool execution
        this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
            const { name, arguments: args } = request.params;

            try {
                switch (name) {
                    case 'list_emails':
                        return await this.listEmails(args?.count || 10, args?.folder || 'INBOX', args?.offset || 0);

                    case 'read_email':
                        return await this.readEmail(args.uids, args.folder);

                    case 'search_emails':
                        return await this.searchEmails(args?.query || '', {
                            count: args?.count || 10,
                            offset: args?.offset || 0,
                            dateFrom: args?.dateFrom || null,
                            dateTo: args?.dateTo || null,
                            sender: args?.sender || null,
                            unreadOnly: args?.unreadOnly || false,
                            flaggedOnly: args?.flaggedOnly || false,
                            folder: args?.folder || 'INBOX'
                        });

                    case 'delete_emails':
                        return await this.deleteEmails(args.uids, args.folder);

                    case 'archive_emails':
                        return await this.archiveEmails(args.uids, args.folder);

                    case 'mark_as_read':
                        return await this.markAsRead(args.uids, args.folder);

                    case 'mark_as_unread':
                        return await this.markAsUnread(args.uids, args.folder);

                    case 'flag_emails':
                        return await this.flagEmails(args.uids, args.folder);

                    case 'unflag_emails':
                        return await this.unflagEmails(args.uids, args.folder);

                    case 'move_emails':
                        return await this.moveEmails(args.uids, args.folderName, args.sourceFolder);

                    case 'list_folders':
                        return await this.listFolders();

                    case 'create_draft':
                        return await this.createDraft(args);

                    case 'send_email':
                        return await this.sendEmail(args);

                    case 'create_calendar_event':
                        return await this.createCalendarEvent(args);

                    case 'get_daily_briefing':
                        return await this.getDailyBriefing(args?.unreadLimit || 15, args?.flaggedLimit || 10);

                    case 'get_attachment':
                        return await this.getAttachment(args);

                    default:
                        throw new Error(`Unknown tool: ${name}`);
                }
            } catch (error) {
                return {
                    content: [
                        {
                            type: 'text',
                            text: `Error: ${error.message}`
                        }
                    ]
                };
            }
        });
    }

    /**
     * Create IMAP connection using app-specific password (like the working test script)
     */
    async createImapConnection() {
        return new Promise((resolve, reject) => {
            if (!process.env.YAHOO_EMAIL || !process.env.YAHOO_APP_PASSWORD) {
                const error = new Error('YAHOO_EMAIL or YAHOO_APP_PASSWORD environment variables are not set');
                console.error('[IMAP] Configuration error:', error.message);
                reject(error);
                return;
            }

            const imap = new Imap({
                user: process.env.YAHOO_EMAIL,
                password: process.env.YAHOO_APP_PASSWORD,
                host: 'imap.mail.yahoo.com',
                port: 993,
                tls: true,
                authTimeout: 30000,
                connTimeout: 30000,
                tlsOptions: {
                    rejectUnauthorized: true,
                    servername: 'imap.mail.yahoo.com',
                    minVersion: 'TLSv1.2'
                }
            });

            // Add connection timeout handler (35 seconds)
            const connectionTimeout = setTimeout(() => {
                console.error('[IMAP] Connection timeout after 35 seconds');
                imap.end();
                reject(new Error('Connection timed out. Service may have been sleeping (Render spindown). Please try again.'));
            }, 35000);

            imap.once('ready', () => {
                clearTimeout(connectionTimeout);
                resolve(imap);
            });

            imap.once('error', (err) => {
                clearTimeout(connectionTimeout);
                console.error('[IMAP] Connection error:', err.message);

                // Provide enhanced error messages based on error type
                let errorMessage = err.message;

                // Authentication errors
                if (err.message.includes('Invalid credentials') ||
                    err.message.includes('authentication failed') ||
                    err.message.includes('AUTHENTICATIONFAILED')) {
                    errorMessage = `Authentication failed: ${err.message}. Please check Yahoo Mail app password. Regenerate at https://login.yahoo.com/account/security`;
                }
                // Network/connection errors
                else if (err.message.includes('ENOTFOUND') ||
                         err.message.includes('ECONNREFUSED') ||
                         err.message.includes('ETIMEDOUT') ||
                         err.message.includes('getaddrinfo')) {
                    errorMessage = `Cannot connect to Yahoo Mail servers: ${err.message}. Check internet connection.`;
                }
                // Timeout errors
                else if (err.message.includes('Timed out') ||
                         err.message.includes('timeout')) {
                    errorMessage = `Connection timed out: ${err.message}. Service may have been sleeping (Render spindown). Please try again.`;
                }

                reject(new Error(errorMessage));
            });

            imap.connect();
        });
    }

    /**
     * List recent emails with enriched metadata
     */
    async listEmails(count = 10, folder = 'INBOX', offset = 0) {
        // Validate count parameter
        if (count < 1) {
            return {
                content: [{
                    type: 'text',
                    text: 'Error: count must be at least 1'
                }]
            };
        }

        if (count > 50) {
            return {
                content: [{
                    type: 'text',
                    text: 'Error: count cannot exceed 50 (use search or filters for larger results)'
                }]
            };
        }

        // Validate offset
        if (offset < 0) {
            return {
                content: [{
                    type: 'text',
                    text: 'Error: offset must be non-negative'
                }]
            };
        }

        const imap = await this.createImapConnection();

        return new Promise((resolve, reject) => {
            imap.openBox(folder, true, (err, box) => {
                if (err) {
                    imap.end();
                    reject(new Error(`Failed to open folder "${folder}": ${err.message}`));
                    return;
                }

                const total = box.messages.total;

                if (total === 0) {
                    imap.end();
                    resolve({
                        content: [{
                            type: 'text',
                            text: JSON.stringify({
                                emails: [],
                                totalCount: 0,
                                offset: 0,
                                limit: count,
                                folder: folder
                            }, null, 2)
                        }]
                    });
                    return;
                }

                // Calculate range with offset
                // If total=100, offset=10, count=10: fetch messages 81-90 (reversed for newest first)
                const startSeq = Math.max(1, total - offset - count + 1);
                const endSeq = Math.max(1, total - offset);

                if (startSeq > endSeq) {
                    imap.end();
                    resolve({
                        content: [{
                            type: 'text',
                            text: JSON.stringify({
                                emails: [],
                                totalCount: total,
                                offset: offset,
                                limit: count,
                                folder: folder,
                                message: 'Offset exceeds available messages'
                            }, null, 2)
                        }]
                    });
                    return;
                }

                // Fetch with struct for attachments and size
                const fetch = imap.seq.fetch(`${startSeq}:${endSeq}`, {
                    bodies: 'HEADER.FIELDS (FROM TO SUBJECT DATE)',
                    struct: true
                });

                const emails = [];

                fetch.on('message', (msg, seqno) => {
                    let header = '';
                    let attrs = null;

                    msg.on('body', (stream, info) => {
                        stream.on('data', (chunk) => {
                            header += chunk.toString('ascii');
                        });
                    });

                    msg.once('attributes', (attributes) => {
                        attrs = attributes;
                    });

                    msg.once('end', () => {
                        const parsed = Imap.parseHeader(header);

                        emails.push({
                            uid: attrs.uid,                          // NEW: Permanent UID
                            sequenceNumber: seqno,                   // Legacy reference
                            from: parsed.from?.[0] || 'Unknown',
                            subject: parsed.subject?.[0] || 'No Subject',
                            date: parsed.date?.[0] || 'Unknown Date',
                            size: attrs.size || 0,                   // NEW: Message size in bytes
                            flags: attrs.flags || [],                // NEW: IMAP flags
                            hasAttachments: this.hasAttachments(attrs.struct) // NEW
                        });
                    });
                });

                fetch.once('error', (err) => {
                    imap.end();
                    reject(err);
                });

                fetch.once('end', () => {
                    imap.end();

                    // Sort by sequence number (newest first)
                    emails.sort((a, b) => b.sequenceNumber - a.sequenceNumber);

                    resolve({
                        content: [{
                            type: 'text',
                            text: JSON.stringify({
                                emails: emails,
                                totalCount: total,
                                offset: offset,
                                limit: count,
                                folder: folder
                            }, null, 2)
                        }]
                    });
                });
            });
        });
    }

    /**
     * Read specific emails by UIDs (supports batch reading)
     */
    async readEmail(uids, folder = 'INBOX') {
        // Support both single number and array for backward compatibility
        if (!Array.isArray(uids)) {
            uids = [uids];
        }

        return this.readEmails(uids, folder);
    }

    /**
     * Search emails with advanced filters
     */
    async searchEmails(query, options = {}) {
        const {
            count = 10,
            offset = 0,
            dateFrom = null,
            dateTo = null,
            sender = null,
            unreadOnly = false,
            flaggedOnly = false,
            folder = 'INBOX'
        } = options;

        // Validate query parameter (allow empty for date-only searches)
        if (query === undefined || query === null) {
            return {
                content: [{
                    type: 'text',
                    text: 'Error: query is required (use empty string "" for searches without text criteria)'
                }]
            };
        }

        // Validate count parameter
        if (count < 1) {
            return {
                content: [{
                    type: 'text',
                    text: 'Error: count must be at least 1'
                }]
            };
        }

        // Validate offset parameter
        if (offset < 0) {
            return {
                content: [{
                    type: 'text',
                    text: 'Error: offset must be non-negative'
                }]
            };
        }

        const imap = await this.createImapConnection();

        return new Promise((resolve, reject) => {
            imap.openBox(folder, true, (err, box) => {
                if (err) {
                    imap.end();
                    reject(new Error(`Failed to open folder "${folder}": ${err.message}`));
                    return;
                }

                // Build search criteria
                const criteria = [];

                // Text search (subject or from)
                if (query && query.trim().length > 0) {
                    criteria.push([
                        'OR',
                        ['HEADER', 'SUBJECT', query],
                        ['HEADER', 'FROM', query]
                    ]);
                }

                // Sender filter
                if (sender && sender.trim().length > 0) {
                    criteria.push(['HEADER', 'FROM', sender]);
                }

                // Date range filters
                if (dateFrom) {
                    try {
                        const fromDate = new Date(dateFrom);
                        if (!isNaN(fromDate.getTime())) {
                            criteria.push(['SINCE', fromDate]);
                        }
                    } catch (e) {
                        imap.end();
                        reject(new Error(`Invalid dateFrom format: ${dateFrom}. Use ISO 8601 format.`));
                        return;
                    }
                }

                if (dateTo) {
                    try {
                        const toDate = new Date(dateTo);
                        if (!isNaN(toDate.getTime())) {
                            criteria.push(['BEFORE', toDate]);
                        }
                    } catch (e) {
                        imap.end();
                        reject(new Error(`Invalid dateTo format: ${dateTo}. Use ISO 8601 format.`));
                        return;
                    }
                }

                // Unread only filter
                if (unreadOnly) {
                    criteria.push('UNSEEN');
                }

                // Flagged/starred only filter
                if (flaggedOnly) {
                    criteria.push('FLAGGED');
                }

                // If no criteria, search all
                if (criteria.length === 0) {
                    criteria.push('ALL');
                }

                // CRITICAL: imap.search() returns UIDs by default (NOT sequence numbers)
                imap.search(criteria, (err, results) => {
                    if (err) {
                        imap.end();
                        reject(err);
                        return;
                    }

                    if (!results || results.length === 0) {
                        imap.end();
                        resolve({
                            content: [{
                                type: 'text',
                                text: JSON.stringify({
                                    emails: [],
                                    totalMatches: 0,
                                    query: query,
                                    filters: options,
                                    folder: folder
                                }, null, 2)
                            }]
                        });
                        return;
                    }

                    // results are UIDs in ascending (oldest-first) order. Paginate newest-first:
                    // offset=0 means "the most recent `count` matches", offset=count means the
                    // next page back, etc. (Previously `offset` was ignored entirely and this
                    // always sliced the same last `count` items regardless of offset.)
                    const endIndex = results.length - offset;
                    const startIndex = Math.max(0, endIndex - count);
                    const limitedResults = endIndex > 0 ? results.slice(startIndex, endIndex) : [];

                    if (limitedResults.length === 0) {
                        imap.end();
                        resolve({
                            content: [{
                                type: 'text',
                                text: JSON.stringify({
                                    emails: [],
                                    totalMatches: results.length,
                                    returned: 0,
                                    offset: offset,
                                    query: query,
                                    filters: options,
                                    folder: folder,
                                    message: 'Offset exceeds available matches'
                                }, null, 2)
                            }]
                        });
                        return;
                    }

                    // Fetch details for these UIDs
                    const fetch = imap.fetch(limitedResults, {
                        bodies: 'HEADER.FIELDS (FROM TO SUBJECT DATE)',
                        struct: true
                    });

                    const emails = [];

                    fetch.on('message', (msg, seqno) => {
                        let header = '';
                        let attrs = null;

                        msg.on('body', (stream, info) => {
                            stream.on('data', (chunk) => {
                                header += chunk.toString('ascii');
                            });
                        });

                        msg.once('attributes', (attributes) => {
                            attrs = attributes;
                        });

                        msg.once('end', () => {
                            const parsed = Imap.parseHeader(header);
                            emails.push({
                                uid: attrs.uid,
                                sequenceNumber: seqno,
                                from: parsed.from?.[0] || 'Unknown',
                                subject: parsed.subject?.[0] || 'No Subject',
                                date: parsed.date?.[0] || 'Unknown Date',
                                size: attrs.size || 0,
                                flags: attrs.flags || [],
                                hasAttachments: this.hasAttachments(attrs.struct)
                            });
                        });
                    });

                    fetch.once('error', (err) => {
                        imap.end();
                        reject(err);
                    });

                    fetch.once('end', () => {
                        imap.end();

                        // Sort by UID (newest first typically)
                        emails.sort((a, b) => b.uid - a.uid);

                        resolve({
                            content: [{
                                type: 'text',
                                text: JSON.stringify({
                                    emails: emails,
                                    totalMatches: results.length,
                                    returned: emails.length,
                                    offset: offset,
                                    query: query,
                                    filters: options,
                                    folder: folder
                                }, null, 2)
                            }]
                        });
                    });
                });
            });
        });
    }

    /**
     * Validate sequence numbers array for all email operations
     * @returns {string|null} Error message if invalid, null if valid
     */
    validateSequenceNumbers(sequenceNumbers) {
        if (!sequenceNumbers) {
            return 'sequenceNumbers is required';
        }

        if (!Array.isArray(sequenceNumbers)) {
            return 'sequenceNumbers must be an array';
        }

        if (sequenceNumbers.length === 0) {
            return 'sequenceNumbers cannot be empty';
        }

        const invalidValues = sequenceNumbers.filter(n => n === undefined || n === null || typeof n !== 'number');
        if (invalidValues.length > 0) {
            return 'sequenceNumbers contains invalid values (must be numbers)';
        }

        return null;
    }

    /**
     * Helper method for batch email modification operations using UIDs
     */
    async modifyEmails(uids, operation, operationName, folder = 'INBOX') {
        // Validate input
        const validationError = this.validateUIDs(uids);
        if (validationError) {
            return {
                content: [{
                    type: 'text',
                    text: `Error: ${validationError}`
                }]
            };
        }

        const imap = await this.createImapConnection();

        return new Promise((resolve, reject) => {
            imap.openBox(folder, false, (err, box) => {  // false = read-write mode
                if (err) {
                    imap.end();
                    reject(new Error(`Failed to open folder "${folder}": ${err.message}`));
                    return;
                }

                const successfulUIDs = [];
                const failedUIDs = [];
                let processedCount = 0;

                // Process each UID individually to ensure all are processed
                const processNextUID = () => {
                    if (processedCount >= uids.length) {
                        // All UIDs processed
                        imap.end();

                        if (failedUIDs.length === uids.length) {
                            // All failed
                            reject(new Error(`Failed to ${operationName} ${failedUIDs.length} email(s). UIDs may not exist: ${failedUIDs.join(', ')}`));
                        } else if (successfulUIDs.length > 0) {
                            // At least some succeeded
                            const message = failedUIDs.length > 0
                                ? `Successfully ${operationName} ${successfulUIDs.length} of ${uids.length} email(s). ` +
                                  `Successful: ${successfulUIDs.join(', ')}. Failed: ${failedUIDs.join(', ')}`
                                : `Successfully ${operationName} ${successfulUIDs.length} email(s) with UIDs: ${successfulUIDs.join(', ')}`;

                            resolve({
                                content: [{
                                    type: 'text',
                                    text: message
                                }]
                            });
                        } else {
                            reject(new Error(`Failed to ${operationName} any emails`));
                        }
                        return;
                    }

                    const uid = uids[processedCount];
                    processedCount++;

                    // Execute the UID-based operation for this single UID
                    operation(imap, uid.toString(), (err) => {
                        if (err) {
                            console.error(`[UID ${uid}] Failed to ${operationName}:`, err.message);
                            failedUIDs.push(uid);
                        } else {
                            successfulUIDs.push(uid);
                        }

                        // Continue to next UID (don't stop on errors)
                        processNextUID();
                    });
                };

                // Start processing
                processNextUID();
            });
        });
    }

    /**
     * Helper method for reading multiple emails using UIDs
     */
    async readEmails(uids, folder = 'INBOX') {
        // Validate input
        const validationError = this.validateUIDs(uids);
        if (validationError) {
            return {
                content: [{
                    type: 'text',
                    text: `Error: ${validationError}`
                }]
            };
        }

        const imap = await this.createImapConnection();

        return new Promise((resolve, reject) => {
            imap.openBox(folder, true, (err, box) => {  // true = read-only mode
                if (err) {
                    imap.end();
                    reject(new Error(`Failed to open folder "${folder}": ${err.message}`));
                    return;
                }

                const source = uids.join(',');

                // CRITICAL: Use imap.fetch() (NOT imap.seq.fetch) for UID-based fetch
                const fetch = imap.fetch(source, {
                    bodies: '',
                    struct: true
                });

                // Each message's simpleParser callback resolves independently of the others,
                // and fetch's 'end' event fires as soon as all messages have streamed off the
                // wire — not once they've finished parsing. Collecting a promise per message
                // and awaiting them all before resolving (instead of relying on fetch.once('end')
                // to mean "parsing is done") is what fixes the empty/incomplete results.
                const foundUIDs = new Set();
                const parsePromises = [];

                fetch.on('message', (msg, seqno) => {
                    let buffer = '';
                    let attrs = null;

                    msg.on('body', (stream, info) => {
                        stream.on('data', (chunk) => {
                            buffer += chunk.toString('ascii');
                        });
                    });

                    msg.once('attributes', (attributes) => {
                        attrs = attributes;
                        foundUIDs.add(attributes.uid);
                    });

                    parsePromises.push(new Promise((resolveParse) => {
                        msg.once('end', () => {
                            simpleParser(buffer, (err, parsed) => {
                                if (err) {
                                    console.error('Error parsing email:', err);
                                    resolveParse(null);
                                    return;
                                }

                                resolveParse({
                                    uid: attrs.uid,
                                    sequenceNumber: seqno,  // Still include for reference
                                    from: parsed.from?.text || 'Unknown',
                                    to: parsed.to?.text || 'Unknown',
                                    subject: parsed.subject || 'No Subject',
                                    date: parsed.date || 'Unknown Date',
                                    size: attrs.size || 0,
                                    flags: attrs.flags || [],
                                    hasAttachments: this.hasAttachments(attrs.struct),
                                    attachmentNames: (parsed.attachments || []).map(a => a.filename || '(unnamed attachment)'),
                                    content: parsed.text || parsed.html || 'No content available'
                                });
                            });
                        });
                    }));
                });

                fetch.once('error', (err) => {
                    imap.end();
                    reject(err);
                });

                fetch.once('end', async () => {
                    imap.end();

                    const emails = (await Promise.all(parsePromises)).filter(Boolean);

                    // Check for missing UIDs
                    const missingUIDs = uids.filter(uid => !foundUIDs.has(uid));
                    if (missingUIDs.length > 0) {
                        reject(new Error(
                            `UIDs not found: ${missingUIDs.join(', ')}. ` +
                            `Found ${emails.length} of ${uids.length} requested emails. ` +
                            `Missing UIDs may have been deleted or moved to another folder.`
                        ));
                        return;
                    }

                    // Sort by UID for consistent output
                    emails.sort((a, b) => a.uid - b.uid);

                    // Format output
                    const emailContent = emails.map(email =>
                        `📧 Email UID: ${email.uid} (Seq #${email.sequenceNumber})\n\n` +
                        `From: ${email.from}\n` +
                        `To: ${email.to}\n` +
                        `Subject: ${email.subject}\n` +
                        `Date: ${email.date}\n` +
                        `Size: ${email.size} bytes\n` +
                        `Flags: ${email.flags.join(', ') || 'None'}\n` +
                        `Has Attachments: ${email.hasAttachments ? `Yes (${email.attachmentNames.join(', ')})` : 'No'}\n\n` +
                        `--- Content ---\n` +
                        `${email.content}`
                    ).join('\n\n' + '='.repeat(80) + '\n\n');

                    resolve({
                        content: [{
                            type: 'text',
                            text: emailContent
                        }]
                    });
                });
            });
        });
    }

    /**
     * Mark emails as read
     */
    async markAsRead(uids, folder = 'INBOX') {
        return this.modifyEmails(
            uids,
            (imap, source, callback) => imap.addFlags(source, '\\Seen', callback),  // NO .seq
            'marked as read',
            folder
        );
    }

    /**
     * Mark emails as unread
     */
    async markAsUnread(uids, folder = 'INBOX') {
        return this.modifyEmails(
            uids,
            (imap, source, callback) => imap.delFlags(source, '\\Seen', callback),  // NO .seq
            'marked as unread',
            folder
        );
    }

    /**
     * Flag emails as important/starred
     */
    async flagEmails(uids, folder = 'INBOX') {
        return this.modifyEmails(
            uids,
            (imap, source, callback) => imap.addFlags(source, '\\Flagged', callback),  // NO .seq
            'flagged',
            folder
        );
    }

    /**
     * Remove flag/star from emails
     */
    async unflagEmails(uids, folder = 'INBOX') {
        return this.modifyEmails(
            uids,
            (imap, source, callback) => imap.delFlags(source, '\\Flagged', callback),  // NO .seq
            'unflagged',
            folder
        );
    }

    /**
     * Delete emails (move to Trash)
     */
    async deleteEmails(uids, folder = 'INBOX') {
        return this.modifyEmails(
            uids,
            (imap, source, callback) => imap.move(source, 'Trash', callback),  // NO .seq
            'moved to Trash',
            folder
        );
    }

    /**
     * Archive emails
     */
    async archiveEmails(uids, folder = 'INBOX') {
        return this.modifyEmails(
            uids,
            (imap, source, callback) => imap.move(source, 'Archive', callback),  // NO .seq
            'archived',
            folder
        );
    }

    /**
     * Move emails to a specific folder
     */
    async moveEmails(uids, folderName, sourceFolder = 'INBOX') {
        return this.modifyEmails(
            uids,
            (imap, source, callback) => imap.move(source, folderName, callback),  // NO .seq
            `moved to ${folderName}`,
            sourceFolder
        );
    }

    /**
     * Helper: Detect if email has attachments from BODYSTRUCTURE
     */
    hasAttachments(struct) {
        if (!struct || !Array.isArray(struct)) return false;

        // Recursive check for attachment disposition
        const checkPart = (part) => {
            if (!part) return false;

            // Check if this part is an attachment
            if (part.disposition && part.disposition.type === 'attachment') {
                return true;
            }

            // Recursively check sub-parts
            if (Array.isArray(part)) {
                return part.some(p => checkPart(p));
            }

            return false;
        };

        return checkPart(struct);
    }

    /**
     * Helper: Flatten nested folder structure for list_folders
     */
    flattenFolders(boxes, parent = null) {
        const result = [];

        for (const [name, box] of Object.entries(boxes)) {
            const fullName = parent ? `${parent}/${name}` : name;

            // Skip NOSELECT folders (can't select them)
            const isNoSelect = box.attribs && box.attribs.includes('\\Noselect');

            result.push({
                name: fullName,
                delimiter: box.delimiter || '/',
                flags: box.attribs || [],
                selectable: !isNoSelect
            });

            // Recursively process children
            if (box.children) {
                result.push(...this.flattenFolders(box.children, fullName));
            }
        }

        return result;
    }

    /**
     * Helper: Validate UIDs array
     */
    validateUIDs(uids) {
        if (!uids) {
            return 'uids is required';
        }

        if (!Array.isArray(uids)) {
            return 'uids must be an array';
        }

        if (uids.length === 0) {
            return 'uids cannot be empty';
        }

        const invalidValues = uids.filter(n =>
            n === undefined ||
            n === null ||
            typeof n !== 'number' ||
            n <= 0 ||
            !Number.isInteger(n)
        );

        if (invalidValues.length > 0) {
            return 'uids contains invalid values (must be positive integers)';
        }

        return null;
    }

    /**
     * List all available IMAP folders
     */
    async listFolders() {
        const imap = await this.createImapConnection();

        return new Promise((resolve, reject) => {
            imap.getBoxes((err, boxes) => {
                imap.end();

                if (err) {
                    reject(new Error(`Failed to retrieve folders: ${err.message}`));
                    return;
                }

                const folders = this.flattenFolders(boxes);

                resolve({
                    content: [{
                        type: 'text',
                        text: JSON.stringify({
                            folders: folders,
                            count: folders.length
                        }, null, 2)
                    }]
                });
            });
        });
    }

    /**
     * Build a raw RFC822 message buffer without sending it, for saving as a draft
     * or as a Sent-folder backup copy. Reuses nodemailer's own MIME composer so
     * headers/encoding are correct instead of hand-rolling MIME.
     */
    async buildRawMessage({ from, to, cc, subject, text, inReplyTo, references }) {
        return new Promise((resolve, reject) => {
            const mail = new MailComposer({
                from,
                to,
                cc: cc || undefined,
                subject,
                text,
                inReplyTo: inReplyTo || undefined,
                references: references || undefined
            });
            mail.compile().build((err, message) => {
                if (err) return reject(err);
                resolve(message);
            });
        });
    }

    /**
     * SMTP transport for sending mail, reusing the same Yahoo app-password
     * credentials already used for IMAP.
     */
    getSmtpTransport() {
        if (!process.env.YAHOO_EMAIL || !process.env.YAHOO_APP_PASSWORD) {
            throw new Error('YAHOO_EMAIL or YAHOO_APP_PASSWORD environment variables are not set');
        }
        return nodemailer.createTransport({
            host: 'smtp.mail.yahoo.com',
            port: 465,
            secure: true,
            auth: {
                user: process.env.YAHOO_EMAIL,
                pass: process.env.YAHOO_APP_PASSWORD
            }
        });
    }

    /**
     * Look up threading headers (Message-ID, References, Subject) for the email
     * a draft/send is replying to, so the reply threads correctly in Yahoo Mail
     * and other clients.
     */
    async getMessageHeadersForReply(uid, folder = 'INBOX') {
        const imap = await this.createImapConnection();
        return new Promise((resolve, reject) => {
            imap.openBox(folder, true, (err) => {
                if (err) {
                    imap.end();
                    reject(new Error(`Failed to open folder "${folder}": ${err.message}`));
                    return;
                }

                const fetch = imap.fetch(String(uid), { bodies: 'HEADER.FIELDS (MESSAGE-ID SUBJECT REFERENCES FROM)' });
                let header = '';
                let found = false;

                fetch.on('message', (msg) => {
                    found = true;
                    msg.on('body', (stream) => {
                        stream.on('data', (chunk) => { header += chunk.toString('ascii'); });
                    });
                });

                fetch.once('error', (err) => {
                    imap.end();
                    reject(err);
                });

                fetch.once('end', () => {
                    imap.end();
                    if (!found) {
                        reject(new Error(`UID ${uid} not found in ${folder}`));
                        return;
                    }
                    const parsed = Imap.parseHeader(header);
                    resolve({
                        messageId: parsed['message-id']?.[0] || null,
                        subject: parsed.subject?.[0] || '',
                        references: parsed.references?.[0] || null
                    });
                });
            });
        });
    }

    /**
     * Resolve reply threading fields (In-Reply-To, References, "Re:" subject)
     * shared by create_draft and send_email. Failure to load the original
     * message's headers is non-fatal — the draft/send still proceeds untreaded.
     */
    async resolveReplyFields(subject, inReplyToUid, inReplyToFolder, toolName) {
        let inReplyTo = null, references = null, finalSubject = subject;
        if (inReplyToUid) {
            try {
                const headers = await this.getMessageHeadersForReply(inReplyToUid, inReplyToFolder);
                inReplyTo = headers.messageId;
                references = [headers.references, headers.messageId].filter(Boolean).join(' ');
                if (!/^re:/i.test(finalSubject)) {
                    finalSubject = /^re:/i.test(headers.subject) ? headers.subject : `Re: ${finalSubject}`;
                }
            } catch (e) {
                console.error(`[${toolName}] Could not load reply headers for UID ${inReplyToUid}:`, e.message);
            }
        }
        return { inReplyTo, references, finalSubject };
    }

    /**
     * Save a new email as a draft (IMAP APPEND to the Drafts folder). Does not send it.
     */
    async createDraft(args) {
        const { to, cc = '', subject, text, inReplyToUid, inReplyToFolder = 'INBOX' } = args || {};
        if (!to || !subject || !text) {
            return { content: [{ type: 'text', text: 'Error: to, subject, and text are required' }] };
        }

        const { inReplyTo, references, finalSubject } = await this.resolveReplyFields(
            subject, inReplyToUid, inReplyToFolder, 'create_draft'
        );

        const raw = await this.buildRawMessage({
            from: process.env.YAHOO_EMAIL,
            to, cc, subject: finalSubject, text, inReplyTo, references
        });

        const draftFolder = process.env.YAHOO_DRAFTS_FOLDER || 'Draft';
        const imap = await this.createImapConnection();

        return new Promise((resolve, reject) => {
            imap.append(raw, { mailbox: draftFolder, flags: ['\\Draft'] }, (err) => {
                imap.end();
                if (err) {
                    reject(new Error(
                        `Failed to save draft to "${draftFolder}": ${err.message}. ` +
                        `If this folder doesn't exist on your account, run list_folders to find the real drafts ` +
                        `folder name and set YAHOO_DRAFTS_FOLDER to match.`
                    ));
                    return;
                }
                resolve({
                    content: [{
                        type: 'text',
                        text: `Draft saved to "${draftFolder}": "${finalSubject}" to ${to}`
                    }]
                });
            });
        });
    }

    /**
     * Send an email via SMTP, then best-effort save a copy to Sent (in case
     * Yahoo's SMTP submission doesn't already do this automatically).
     */
    async sendEmail(args) {
        const { to, cc = '', bcc = '', subject, text, inReplyToUid, inReplyToFolder = 'INBOX' } = args || {};
        if (!to || !subject || !text) {
            return { content: [{ type: 'text', text: 'Error: to, subject, and text are required' }] };
        }

        const { inReplyTo, references, finalSubject } = await this.resolveReplyFields(
            subject, inReplyToUid, inReplyToFolder, 'send_email'
        );

        const transport = this.getSmtpTransport();
        const info = await transport.sendMail({
            from: process.env.YAHOO_EMAIL,
            to,
            cc: cc || undefined,
            bcc: bcc || undefined,
            subject: finalSubject,
            text,
            inReplyTo: inReplyTo || undefined,
            references: references || undefined
        });

        try {
            const raw = await this.buildRawMessage({
                from: process.env.YAHOO_EMAIL, to, cc, subject: finalSubject, text, inReplyTo, references
            });
            const sentFolder = process.env.YAHOO_SENT_FOLDER || 'Sent';
            const sentImap = await this.createImapConnection();
            await new Promise((resolve) => {
                sentImap.append(raw, { mailbox: sentFolder, flags: ['\\Seen'] }, (err) => {
                    sentImap.end();
                    if (err) console.error(`[send_email] Could not save copy to "${sentFolder}":`, err.message);
                    resolve();
                });
            });
        } catch (e) {
            console.error('[send_email] Sent-folder backup failed:', e.message);
        }

        return {
            content: [{
                type: 'text',
                text: `Email sent to ${to}${cc ? `, cc: ${cc}` : ''}. Subject: "${finalSubject}". Message ID: ${info.messageId}`
            }]
        };
    }

    /**
     * CalDAV client for Yahoo Calendar, reusing the same app-password credentials.
     * Yahoo's CalDAV support isn't officially documented, so this is best-effort —
     * verify against a real account before relying on it.
     */
    async getCalDavClient() {
        if (!process.env.YAHOO_EMAIL || !process.env.YAHOO_APP_PASSWORD) {
            throw new Error('YAHOO_EMAIL or YAHOO_APP_PASSWORD environment variables are not set');
        }
        return createDAVClient({
            serverUrl: 'https://caldav.calendar.yahoo.com',
            credentials: {
                username: process.env.YAHOO_EMAIL,
                password: process.env.YAHOO_APP_PASSWORD
            },
            authMethod: 'Basic',
            defaultAccountType: 'caldav'
        });
    }

    buildIcsEvent({ uid, title, start, end, description, location }) {
        const toIcsDate = (iso) => {
            const d = new Date(iso);
            if (isNaN(d.getTime())) throw new Error(`Invalid date: ${iso}`);
            return d.toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';
        };
        const escapeIcs = (s = '') => String(s).replace(/([,;\\])/g, '\\$1').replace(/\n/g, '\\n');

        return [
            'BEGIN:VCALENDAR',
            'VERSION:2.0',
            'PRODID:-//yahoo-mail-mcp-server//EN',
            'BEGIN:VEVENT',
            `UID:${uid}`,
            `DTSTAMP:${toIcsDate(new Date().toISOString())}`,
            `DTSTART:${toIcsDate(start)}`,
            `DTEND:${toIcsDate(end)}`,
            `SUMMARY:${escapeIcs(title)}`,
            description ? `DESCRIPTION:${escapeIcs(description)}` : null,
            location ? `LOCATION:${escapeIcs(location)}` : null,
            'END:VEVENT',
            'END:VCALENDAR'
        ].filter(Boolean).join('\r\n');
    }

    /**
     * Create an event on Yahoo Calendar via CalDAV.
     */
    async createCalendarEvent(args) {
        const { title, start, description = '', location = '' } = args || {};
        let { end } = args || {};

        if (!title || !start) {
            return { content: [{ type: 'text', text: 'Error: title and start are required' }] };
        }

        const startDate = new Date(start);
        if (isNaN(startDate.getTime())) {
            return { content: [{ type: 'text', text: `Error: invalid start date "${start}"` }] };
        }
        if (!end) {
            end = new Date(startDate.getTime() + 30 * 60000).toISOString();
        }

        const client = await this.getCalDavClient();
        const calendars = await client.fetchCalendars();
        if (!calendars.length) {
            return { content: [{ type: 'text', text: 'Error: no Yahoo calendars found for this account via CalDAV.' }] };
        }
        const calendar = calendars.find(c => /calendar/i.test(c.displayName || '')) || calendars[0];

        const uid = `${crypto.randomUUID()}@yahoo-mail-mcp`;
        const iCalString = this.buildIcsEvent({ uid, title, start, end, description, location });

        const result = await client.createCalendarObject({ calendar, filename: `${uid}.ics`, iCalString });
        if (!result.ok) {
            throw new Error(
                `CalDAV server responded with status ${result.status} when creating the event. ` +
                `Yahoo's CalDAV support and whether this app password covers it aren't officially documented — ` +
                `verify caldav.calendar.yahoo.com is reachable with these credentials.`
            );
        }

        return {
            content: [{
                type: 'text',
                text: `Event "${title}" created on "${calendar.displayName || 'your calendar'}" from ${start} to ${end}.`
            }]
        };
    }

    /**
     * One-call summary of unread, flagged, and today's INBOX mail.
     */
    async getDailyBriefing(unreadLimit = 15, flaggedLimit = 10) {
        const parseResult = (result) => {
            try {
                const data = JSON.parse(result.content[0].text);
                return { total: data.totalMatches ?? data.totalCount ?? 0, emails: data.emails || [] };
            } catch {
                return { total: 0, emails: [] };
            }
        };

        const startOfToday = new Date();
        startOfToday.setHours(0, 0, 0, 0);

        const [unread, flagged, today] = await Promise.all([
            this.searchEmails('', { count: unreadLimit, unreadOnly: true, folder: 'INBOX' }),
            this.searchEmails('', { count: flaggedLimit, flaggedOnly: true, folder: 'INBOX' }),
            this.searchEmails('', { count: 50, dateFrom: startOfToday.toISOString(), folder: 'INBOX' })
        ]);

        const summary = {
            generatedAt: new Date().toISOString(),
            unread: parseResult(unread),
            flagged: parseResult(flagged),
            receivedToday: parseResult(today)
        };

        return {
            content: [{
                type: 'text',
                text: JSON.stringify(summary, null, 2)
            }]
        };
    }

    /**
     * List an email's attachments, or fetch one as base64 by filename/index.
     */
    async getAttachment(args) {
        const { uid, folder = 'INBOX', filename, attachmentIndex } = args || {};
        if (!uid || typeof uid !== 'number') {
            return { content: [{ type: 'text', text: 'Error: uid (number) is required' }] };
        }

        const imap = await this.createImapConnection();

        const parsed = await new Promise((resolve, reject) => {
            imap.openBox(folder, true, (err) => {
                if (err) {
                    imap.end();
                    reject(new Error(`Failed to open folder "${folder}": ${err.message}`));
                    return;
                }

                const fetch = imap.fetch(String(uid), { bodies: '', struct: true });
                let buffer = '';
                let found = false;

                fetch.on('message', (msg) => {
                    found = true;
                    msg.on('body', (stream) => {
                        stream.on('data', (chunk) => { buffer += chunk.toString('ascii'); });
                    });
                    msg.once('end', () => {
                        simpleParser(buffer, (err, mail) => {
                            imap.end();
                            if (err) { reject(err); return; }
                            resolve(mail);
                        });
                    });
                });

                fetch.once('error', (err) => {
                    imap.end();
                    reject(err);
                });

                fetch.once('end', () => {
                    if (!found) {
                        imap.end();
                        reject(new Error(`UID ${uid} not found in ${folder}`));
                    }
                });
            });
        });

        const attachments = parsed.attachments || [];
        if (attachments.length === 0) {
            return { content: [{ type: 'text', text: `Email UID ${uid} has no attachments.` }] };
        }

        if (!filename && attachmentIndex === undefined) {
            const listing = attachments
                .map((a, i) => `[${i}] ${a.filename || '(unnamed)'} — ${a.contentType}, ${a.size} bytes`)
                .join('\n');
            return {
                content: [{
                    type: 'text',
                    text: `Email UID ${uid} has ${attachments.length} attachment(s):\n${listing}\n\n` +
                        `Call get_attachment again with "filename" or "attachmentIndex" to retrieve one.`
                }]
            };
        }

        const attachment = attachmentIndex !== undefined
            ? attachments[attachmentIndex]
            : attachments.find(a => a.filename === filename);

        if (!attachment) {
            return { content: [{ type: 'text', text: `Error: attachment not found (filename="${filename}", index=${attachmentIndex})` }] };
        }

        const maxBytes = parseInt(process.env.MAX_ATTACHMENT_BYTES || '8000000', 10);
        if (attachment.size > maxBytes) {
            return {
                content: [{
                    type: 'text',
                    text: `Error: "${attachment.filename}" is ${attachment.size} bytes, over the ${maxBytes}-byte ` +
                        `limit for returning through MCP. Increase MAX_ATTACHMENT_BYTES if you need larger files.`
                }]
            };
        }

        return {
            content: [
                { type: 'text', text: `Attachment "${attachment.filename}" (${attachment.contentType}, ${attachment.size} bytes), base64-encoded:` },
                { type: 'text', text: attachment.content.toString('base64') }
            ]
        };
    }

    setupErrorHandling() {
        this.server.onerror = (error) => {
            console.error('[MCP Error]', error);
        };

        process.on('SIGINT', async () => {
            await this.server.close();
            process.exit(0);
        });
    }

    async run() {
        // Check if we should use SSE (HTTP) or stdio transport
        const transportMode = process.env.TRANSPORT_MODE || 'stdio';

        if (transportMode === 'sse') {
            await this.runSSE();
        } else {
            await this.runStdio();
        }
    }

    async runStdio() {
        const transport = new StdioServerTransport();
        await this.server.connect(transport);
        console.error('Yahoo Mail MCP server running on stdio');
    }

    async runSSE() {
        const app = express();
        const port = process.env.PORT || 3000;

        // Log startup configuration
        console.error('[Server] Starting in SSE mode');
        console.error('[Server] Port:', port);
        console.error('[Server] Node version:', process.version);
        console.error('[Server] Environment:', process.env.NODE_ENV || 'development');
        console.error('[Server] Email configured:', !!process.env.YAHOO_EMAIL);
        console.error('[Server] Password configured:', !!process.env.YAHOO_APP_PASSWORD);

        // Enable CORS only for known origins (claude.ai/claude.com by default, configurable).
        // Previously `origin: true` reflected any request's Origin header, which lets any
        // website's JS make credentialed requests against this server.
        const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'https://claude.ai,https://claude.com')
            .split(',').map(o => o.trim()).filter(Boolean);
        app.use(cors({
            origin: (origin, callback) => {
                // No Origin header = non-browser request (curl, server-to-server); allow it.
                if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
                console.error('[CORS] Rejected origin:', origin);
                callback(new Error('Not allowed by CORS'));
            },
            credentials: true,
            methods: ['GET', 'POST', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'X-Requested-With'],
            exposedHeaders: ['Content-Type'],
            maxAge: 86400  // Cache preflight for 24 hours
        }));

        // Parse request bodies for different content types
        // Skip /mcp/message which needs raw body for SSE
        app.use((req, res, next) => {
            if (req.path === '/mcp/message') {
                return next();
            }

            // OAuth token endpoint needs both JSON and URL-encoded support
            if (req.path === '/oauth/token') {
                // Parse both JSON and URL-encoded bodies
                express.json()(req, res, (err) => {
                    if (err) return next(err);
                    express.urlencoded({ extended: true })(req, res, next);
                });
            } else {
                // All other endpoints just need JSON
                express.json()(req, res, next);
            }
        });

        // Request logging middleware
        app.use((req, res, next) => {
            console.error(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
            next();
        });

        // Authentication middleware for MCP endpoints
        const authenticateMCP = (req, res, next) => {
            // Skip auth for health check, OAuth endpoints, and discovery endpoints
            if (req.path === '/health' ||
                req.path === '/' ||
                req.path.startsWith('/.well-known/') ||
                req.path === '/register' ||
                req.path.startsWith('/oauth/')) {
                return next();
            }

            // Check if OAuth is configured
            const oauthConfigured = process.env.OAUTH_CLIENT_ID && process.env.OAUTH_CLIENT_SECRET;

            if (!oauthConfigured) {
                console.error('[Auth] WARNING: OAuth not configured - server is UNSECURED!');
                console.error('[Auth] Set OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET to secure your server');
                return next();
            }

            // Validate OAuth Bearer token
            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                console.error('[Auth] Missing or invalid Authorization header');
                return res.status(401).json({
                    error: 'unauthorized',
                    error_description: 'Bearer token required'
                });
            }

            const token = authHeader.substring(7); // Remove 'Bearer ' prefix

            // Validate token against the persisted store (survives restarts, actually expires)
            if (!this.tokenStore.isValidToken(token)) {
                console.error('[Auth] Invalid or expired access token');
                return res.status(401).json({
                    error: 'invalid_token',
                    error_description: 'The access token is invalid or has expired'
                });
            }

            console.error('[Auth] OAuth authentication successful');
            next();
        };

        // Apply authentication to all MCP endpoints
        app.use(authenticateMCP);

        // Rate limit the token endpoint to slow down credential-guessing/brute-force attempts
        const tokenRateLimiter = rateLimit({
            windowMs: 15 * 60 * 1000,
            max: 20,
            standardHeaders: true,
            legacyHeaders: false,
            message: { error: 'too_many_requests', error_description: 'Too many token requests, try again later.' }
        });

        // Helper function to generate OAuth metadata
        const getOAuthMetadata = (req) => {
            const baseUrl = `https://${req.get('host')}`;
            return {
                issuer: baseUrl,
                authorization_endpoint: `${baseUrl}/oauth/authorize`,
                token_endpoint: `${baseUrl}/oauth/token`,
                grant_types_supported: ['authorization_code', 'client_credentials'],
                response_types_supported: ['code'],
                token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
                code_challenge_methods_supported: ['S256'],
                scopes_supported: ['mcp']
            };
        };

        // Helper function to generate protected resource metadata
        const getProtectedResourceMetadata = (req, resourcePath = '') => {
            const baseUrl = `https://${req.get('host')}`;
            return {
                resource: resourcePath ? `${baseUrl}${resourcePath}` : baseUrl,
                authorization_servers: [baseUrl],
                scopes_supported: ['mcp']
            };
        };

        // OpenID Configuration (superset of OAuth authorization server metadata)
        app.get('/.well-known/openid-configuration', (req, res) => {
            console.error('[OAuth] OpenID configuration requested');
            res.json(getOAuthMetadata(req));
        });

        // OAuth 2.0 Authorization Server Metadata (RFC 8414)
        app.get('/.well-known/oauth-authorization-server', (req, res) => {
            console.error('[OAuth] Authorization server metadata requested');
            res.json(getOAuthMetadata(req));
        });

        app.get('/.well-known/oauth-authorization-server/mcp/sse', (req, res) => {
            console.error('[OAuth] Authorization server metadata for /mcp/sse requested');
            res.json(getOAuthMetadata(req));
        });

        // OAuth Protected Resource Metadata
        app.get('/.well-known/oauth-protected-resource', (req, res) => {
            console.error('[OAuth] Protected resource metadata requested');
            res.json(getProtectedResourceMetadata(req));
        });

        app.get('/.well-known/oauth-protected-resource/mcp/sse', (req, res) => {
            console.error('[OAuth] Protected resource metadata for /mcp/sse requested');
            res.json(getProtectedResourceMetadata(req, '/mcp/sse'));
        });

        // OAuth Authorization Endpoint (Authorization Code Flow)
        app.get('/oauth/authorize', (req, res) => {
            console.error('[OAuth] Authorization request received');
            console.error('[OAuth] Query params:', JSON.stringify(req.query).substring(0, 200));

            const clientId = process.env.OAUTH_CLIENT_ID;
            const {
                response_type,
                client_id,
                redirect_uri,
                state,
                code_challenge,
                code_challenge_method,
                scope
            } = req.query;

            // Validate client_id
            if (client_id !== clientId) {
                console.error('[OAuth] Invalid client_id in authorize request');
                return res.status(400).send('Invalid client_id');
            }

            // Validate response_type
            if (response_type !== 'code') {
                console.error('[OAuth] Unsupported response_type:', response_type);
                return res.status(400).send('Unsupported response_type');
            }

            // Validate redirect_uri against an exact hostname allowlist. The previous check used
            // redirect_uri.includes('claude.ai'), which a URL like https://claude.ai.attacker.com
            // also satisfies — a real open-redirect / auth-code-theft bypass.
            if (!redirect_uri || !isAllowedRedirectUri(redirect_uri)) {
                console.error('[OAuth] Invalid redirect_uri:', redirect_uri);
                return res.status(400).send('Invalid redirect_uri');
            }

            // Generate authorization code (cryptographically random, not derived from timestamp)
            const authCode = crypto.randomBytes(32).toString('base64url');

            // Store auth code with PKCE challenge, persisted with a 60s TTL
            this.tokenStore.setAuthCode(authCode, {
                client_id,
                redirect_uri,
                code_challenge,
                code_challenge_method,
                scope
            }, 60_000);

            console.error('[OAuth] Authorization code generated, redirecting to:', redirect_uri);

            // Redirect back to Claude with authorization code
            const redirectUrl = new URL(redirect_uri);
            redirectUrl.searchParams.append('code', authCode);
            if (state) redirectUrl.searchParams.append('state', state);

            res.redirect(redirectUrl.toString());
        });

        // OAuth Token Endpoint (supports both Authorization Code and Client Credentials flows)
        app.post('/oauth/token', tokenRateLimiter, async (req, res) => {
            console.error('[OAuth] Token request - grant type:', req.body?.grant_type || 'unknown');

            const clientId = process.env.OAUTH_CLIENT_ID;
            const clientSecret = process.env.OAUTH_CLIENT_SECRET;

            if (!clientId || !clientSecret) {
                console.error('[OAuth] Server misconfigured - OAuth credentials not set');
                return res.status(500).json({
                    error: 'server_error',
                    error_description: 'OAuth not configured on server'
                });
            }

            // Extract credentials from Authorization header (Basic Auth) or request body
            let reqClientId, reqClientSecret;
            const authHeader = req.headers.authorization;

            if (authHeader && authHeader.startsWith('Basic ')) {
                const credentials = Buffer.from(authHeader.substring(6), 'base64').toString();
                [reqClientId, reqClientSecret] = credentials.split(':');
            } else {
                reqClientId = req.body?.client_id;
                reqClientSecret = req.body?.client_secret;
            }

            // Validate credentials
            if (reqClientId !== clientId || reqClientSecret !== clientSecret) {
                console.error('[OAuth] Authentication failed - invalid client credentials');
                return res.status(401).json({
                    error: 'invalid_client',
                    error_description: 'Invalid client credentials'
                });
            }

            const grantType = req.body?.grant_type;

            // Handle Authorization Code Grant (with PKCE)
            if (grantType === 'authorization_code') {
                const { code, redirect_uri, code_verifier } = req.body;

                console.error('[OAuth] Authorization code grant - validating code');

                // Validate authorization code (checks existence + expiry, doesn't consume yet)
                if (!this.tokenStore.hasAuthCode(code)) {
                    console.error('[OAuth] Invalid or expired authorization code');
                    return res.status(400).json({
                        error: 'invalid_grant',
                        error_description: 'Invalid or expired authorization code'
                    });
                }

                const authData = this.tokenStore.getAuthCode(code);

                // Validate PKCE code verifier
                if (authData.code_challenge) {
                    const hash = crypto.createHash('sha256').update(code_verifier).digest('base64url');
                    if (hash !== authData.code_challenge) {
                        console.error('[OAuth] PKCE validation failed');
                        return res.status(400).json({
                            error: 'invalid_grant',
                            error_description: 'PKCE validation failed'
                        });
                    }
                }

                // Delete used auth code (one-time use)
                this.tokenStore.consumeAuthCode(code);

                // Generate access token (cryptographically random, persisted with real expiry)
                const accessToken = crypto.randomBytes(32).toString('base64url');
                this.tokenStore.addToken(accessToken, 3600_000, authData.scope || 'mcp');

                console.error('[OAuth] Access token generated from authorization code');

                return res.json({
                    access_token: accessToken,
                    token_type: 'Bearer',
                    expires_in: 3600,
                    scope: authData.scope || 'mcp'
                });
            }

            // Handle Client Credentials Grant
            if (grantType === 'client_credentials') {
                // Generate access token (cryptographically random, persisted with real expiry)
                const accessToken = crypto.randomBytes(32).toString('base64url');
                this.tokenStore.addToken(accessToken, 3600_000, 'mcp');

                console.error('[OAuth] Access token generated via client credentials');

                return res.json({
                    access_token: accessToken,
                    token_type: 'Bearer',
                    expires_in: 3600,
                    scope: 'mcp'
                });
            }

            // Unsupported grant type
            console.error('[OAuth] Unsupported grant type:', grantType);
            res.status(400).json({
                error: 'unsupported_grant_type',
                error_description: 'Supported grant types: authorization_code, client_credentials'
            });
        });

        // Dynamic client registration endpoint (not supported)
        app.post('/register', (req, res) => {
            console.error('[OAuth] Client registration attempted - not supported');
            res.status(404).json({
                error: 'unsupported_operation',
                error_description: 'Dynamic client registration is not supported. Use static OAuth credentials.'
            });
        });

        // Health check endpoint (enhanced with environment info)
        app.get('/health', (req, res) => {
            res.json({
                status: 'ok',
                service: 'yahoo-mail-mcp',
                version: '3.0.0',
                timestamp: new Date().toISOString(),
                environment: {
                    nodeVersion: process.version,
                    platform: process.platform,
                    emailConfigured: !!process.env.YAHOO_EMAIL,
                    passwordConfigured: !!process.env.YAHOO_APP_PASSWORD,
                    transportMode: process.env.TRANSPORT_MODE || 'stdio'
                }
            });
        });

        // SSE endpoint for MCP
        app.get('/mcp/sse', async (req, res) => {
            try {
                console.error('[SSE] New connection established from:', req.ip);
                console.error('[SSE] Origin:', req.headers.origin);
                console.error('[SSE] User-Agent:', req.headers['user-agent']);

                const transport = new SSEServerTransport('/mcp/message', res);

                // Get session ID from transport
                const sessionId = transport.sessionId;
                console.error('[SSE] Session ID:', sessionId);

                // Store the transport for message routing
                this.transports.set(sessionId, transport);

                // Clean up on disconnect
                transport.onclose = () => {
                    console.error('[SSE] Connection closed, cleaning up session:', sessionId);
                    this.transports.delete(sessionId);
                };

                await this.server.connect(transport);
                console.error('[SSE] MCP server connected to transport');
            } catch (error) {
                console.error('[SSE] Error connecting transport:', error);
                if (!res.headersSent) {
                    res.status(500).json({ error: error.message });
                }
            }
        });

        // Message endpoint for SSE
        app.post('/mcp/message', async (req, res) => {
            console.error('[SSE] Received message on /mcp/message');
            console.error('[SSE] Active transports:', this.transports.size);

            // Extract session ID from query or headers (body not parsed yet)
            const sessionId = req.query?.sessionId || req.headers['x-session-id'];
            console.error('[SSE] Session ID from request:', sessionId);

            if (sessionId && this.transports.has(sessionId)) {
                const transport = this.transports.get(sessionId);
                console.error('[SSE] Routing message to transport:', sessionId);
                // Let the transport handle the message
                transport.handlePostMessage(req, res);
            } else {
                // If no session ID or transport not found, try the first available transport
                // (for backwards compatibility with single-connection scenario)
                const firstTransport = Array.from(this.transports.values())[0];
                if (firstTransport) {
                    console.error('[SSE] No session ID, using first available transport');
                    firstTransport.handlePostMessage(req, res);
                } else {
                    console.error('[SSE] No active transport found');
                    res.status(404).json({ error: 'No active SSE connection found' });
                }
            }
        });

        // Streamable HTTP transport (MCP spec 2025-03-26+). This is the transport
        // Claude's custom connectors expect; /mcp/sse + /mcp/message above remain
        // for backwards compatibility with older SSE-only clients.
        app.post('/mcp', async (req, res) => {
            console.error('[MCP] POST /mcp (Streamable HTTP)');
            try {
                const transport = new StreamableHTTPServerTransport({
                    sessionIdGenerator: undefined
                });
                res.on('close', () => transport.close());
                await this.server.connect(transport);
                await transport.handleRequest(req, res, req.body);
            } catch (error) {
                console.error('[MCP] Error handling Streamable HTTP request:', error);
                if (!res.headersSent) {
                    res.status(500).json({
                        jsonrpc: '2.0',
                        error: { code: -32603, message: 'Internal server error' },
                        id: null
                    });
                }
            }
        });

        app.get('/mcp', (req, res) => {
            res.status(405).json({
                jsonrpc: '2.0',
                error: { code: -32000, message: 'Method not allowed: this server runs Streamable HTTP in stateless mode.' },
                id: null
            });
        });

        app.delete('/mcp', (req, res) => {
            res.status(405).json({
                jsonrpc: '2.0',
                error: { code: -32000, message: 'Method not allowed: this server runs Streamable HTTP in stateless mode.' },
                id: null
            });
        });

        // Error handling middleware
        app.use((err, req, res, next) => {
            console.error('[Express] Error:', err);
            res.status(500).json({
                error: 'Internal server error',
                message: err.message
            });
        });

        // Root endpoint
        app.get('/', (req, res) => {
            res.json({
                name: 'Yahoo Mail MCP Server',
                version: '3.0.0',
                description: 'MCP server for Yahoo Mail access via IMAP',
                endpoints: {
                    health: '/health',
                    sse: '/mcp/sse',
                    message: '/mcp/message'
                },
                tools: [
                    'list_emails',
                    'read_email',
                    'search_emails',
                    'delete_emails',
                    'archive_emails',
                    'mark_as_read',
                    'mark_as_unread',
                    'flag_emails',
                    'unflag_emails',
                    'move_emails',
                    'list_folders',
                    'create_draft',
                    'send_email',
                    'create_calendar_event',
                    'get_daily_briefing',
                    'get_attachment'
                ]
            });
        });

        app.listen(port, () => {
            console.error(`Yahoo Mail MCP server running on port ${port}`);
            console.error(`SSE endpoint: http://localhost:${port}/mcp/sse`);
            console.error(`Health check: http://localhost:${port}/health`);
        });
    }
}

// Start the server
const server = new YahooMailMCPServer();
server.run().catch(console.error);
