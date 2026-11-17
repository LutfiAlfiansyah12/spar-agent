/**
 * Persistent run store — a single JSON file under DATA_DIR.
 * Writes are atomic (tmp + rename). Run documents are compact (vector
 * results only, never secrets, never target payloads).
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { SparRunDoc, AnchorInfo } from './scorecard.js';
import { log } from './log.js';

export class SparStore {
  private file: string;
  private docs = new Map<string, SparRunDoc>();

  constructor(dataDir: string) {
    fs.mkdirSync(dataDir, { recursive: true });
    this.file = path.join(dataDir, 'runs.json');
    this.load();
  }

  private load(): void {
    if (!fs.existsSync(this.file)) return;
    try {
      const raw = JSON.parse(fs.readFileSync(this.file, 'utf8')) as { runs?: SparRunDoc[] };
      for (const doc of raw.runs ?? []) this.docs.set(doc.id, doc);
      log.info('run store loaded', { count: this.docs.size });
    } catch (e) {
      log.error('run store load failed — starting empty', { error: String(e).slice(0, 120) });
    }
  }

  private save(): void {
    const tmp = this.file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify({ runs: [...this.docs.values()] }, null, 2));
    fs.renameSync(tmp, this.file);
  }

  put(doc: SparRunDoc): void {
    this.docs.set(doc.id, doc);
    this.save();
  }

  get(id: string): SparRunDoc | undefined {
    return this.docs.get(id);
  }

  updateAnchor(id: string, anchor: AnchorInfo): SparRunDoc | undefined {
    const doc = this.docs.get(id);
    if (!doc) return undefined;
    doc.anchor = { ...anchor, updated_at: new Date().toISOString() };
    this.save();
    return doc;
  }

  get size(): number {
    return this.docs.size;
  }
}
