<?php
/*
 * ai_queue.inc
 * SQLite-based Queue for decoupling AI Log Collector and Analyzer
 */

class AIQueue {
    private $pdo;
    private $db_path = '/var/db/ai_queue.sqlite';

    public function __construct() {
        try {
            $this->pdo = new PDO('sqlite:' . $this->db_path);
            $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->pdo->setAttribute(PDO::ATTR_TIMEOUT, 5); // Wait 5s for lock
            $this->init();
        } catch (PDOException $e) {
            syslog(LOG_ERR, "AI Queue: DB Connection failed: " . $e->getMessage());
            throw $e;
        }
    }

    private function init() {
        $this->pdo->exec("CREATE TABLE IF NOT EXISTS queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            log_line TEXT,
            timestamp INTEGER
        )");
        $this->pdo->exec("CREATE INDEX IF NOT EXISTS idx_ts ON queue (timestamp)");
        // Prune old entries just in case (older than 24h)
        $this->pdo->exec("DELETE FROM queue WHERE timestamp < " . (time() - 86400));
    }

    public function push($ip, $line) {
        // Simple deduplication check for very recent identical items? 
        // No, let the Collector handle cache.
        $stmt = $this->pdo->prepare("INSERT INTO queue (ip, log_line, timestamp) VALUES (?, ?, ?)");
        $stmt->execute([$ip, $line, time()]);
        return $this->pdo->lastInsertId();
    }

    public function pop($limit = 1) {
        try {
            $this->pdo->beginTransaction();
            $stmt = $this->pdo->prepare("SELECT * FROM queue ORDER BY id ASC LIMIT ?");
            $stmt->execute([$limit]);
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            if ($rows) {
                $ids = array_column($rows, 'id');
                $in  = str_repeat('?,', count($ids) - 1) . '?';
                $del = $this->pdo->prepare("DELETE FROM queue WHERE id IN ($in)");
                $del->execute($ids);
            }
            $this->pdo->commit();
            return $rows;
        } catch (Exception $e) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            return [];
        }
    }
}
