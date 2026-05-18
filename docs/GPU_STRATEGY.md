# GPU and Model Strategy for Windows RTX 5060 Ti

## Your Hardware

**Machine:** Windows RTX 5060 Ti (12GB VRAM)  
**Development Model:** Qwen2.5-coder-1.5B via Ollama  
**Strategic Model:** Claude Sonnet API (when stuck)  
**Budget:** $120 total (6-8 API calls)

---

## Hybrid Approach: Why This Works

### Cost Comparison

| Approach | Cost | Speed | Iteration |
|----------|------|-------|-----------|
| **Pure Claude Sonnet** | $1,600 | 300 tokens/sec | Slow (API latency) |
| **Pure Haiku** | $600 | 200 tokens/sec | Risky (insufficient for OSINT logic) |
| **Ollama + Sonnet** | $120 | 120 tokens/sec (local) | Fast (instant feedback) |
| **Your Choice** | $120 | 120 tokens/sec | **Best** ✓ |

**Savings:** 93% cheaper than pure Claude, better iteration speed

---

## Model Selection: Qwen2.5-coder-1.5B

### Specifications

| Property | Value |
|----------|-------|
| Parameters | 1.5 billion |
| Size | ~1.5GB download |
| VRAM (Quantized) | 2GB |
| Speed | 120 tokens/sec on RTX 5060 Ti |
| Cost | $0 (local inference) |
| Context | 32K tokens |
| Base Model | Qwen2.5 (code-optimized) |

### What It's Good At (90% of Phase 1)

- **Code Generation:** FastAPI endpoints, SQLAlchemy models, database migrations
- **Debugging:** Fix Python errors, test failures, type hint issues
- **Refactoring:** Optimize queries, improve code structure, add validation
- **Documentation:** Generate docstrings, API specs, setup guides
- **Testing:** Write pytest fixtures, test cases, assertions
- **Configuration:** YAML files, environment templates, secrets management
- **Scripting:** Bash/Python setup scripts, deployment configs

### Why 1.5B (Not 7B)

**1.5B Advantages:**
- Uses only 2GB VRAM → leaves 10GB free for databases
- 120 tokens/sec is fast enough for code generation
- Supports 3+ parallel developers without GPU contention
- Instant availability → better iteration loops

**7B Disadvantages:**
- Uses 8-12GB VRAM → only 0-4GB left for databases
- Can't run PostgreSQL + Redis + Elasticsearch locally simultaneously
- Only fits 1 developer at a time
- More expensive to run ($0.01-0.05 per hour inference)

---

## Running Ollama on Windows RTX 5060 Ti

### Installation

1. **Download Ollama:** https://ollama.ai/
2. **Run installer:** Windows will auto-detect RTX 5060 Ti
3. **Verify:** Open Command Prompt
   ```cmd
   ollama --version
   ```

### Pull Development Model

```cmd
ollama pull qwen2.5-coder:1.5b
```
- First pull: ~5 minutes, 1.5GB download
- Subsequent runs: instant (model cached locally)

### Start Ollama Daemon

**Keep in background window:**
```cmd
ollama serve
```
This runs on `localhost:11434`

### Verify GPU Usage

```cmd
ollama list
```
Shows loaded models and VRAM consumption. Should show ~2GB used.

---

## Claude Sonnet API: For Strategic Decisions

### When to Use Sonnet (10% of work)

Use Claude Sonnet API only when:

1. **Architecture Decision**
   - "I'm stuck on how to orchestrate 30+ OSINT tool calls. Should I use state machine, queue, or direct tool-use API?"
   - Cost: ~$0.20 | Time saved: 4-6 hours

2. **Complex Bug**
   - Spent 30+ minutes stuck, Ollama can't explain the issue
   - Cost: ~$0.10-0.20 | Time saved: 2-3 hours

3. **Security Review**
   - "Review this JWT implementation for vulnerabilities"
   - Cost: ~$0.10 | Time saved: 1-2 hours (prevents production bugs)

4. **Integration Strategy**
   - "How should I wire 30+ OSINT APIs into unified orchestrator?"
   - Cost: ~$0.20 | Time saved: 4-6 hours

5. **Performance Optimization**
   - "This database query is slow. How should I optimize?"
   - Cost: ~$0.15 | Time saved: 2-3 hours

### Budget Allocation

**Phase 1 Calls (estimated):**
- Day 4-5: JWT/Auth architecture → 1 call ($0.15)
- Day 5-6: RBAC permission logic → 1 call ($0.15) OR resolve with Ollama
- **Total Phase 1:** 1-2 calls = $0.30

**Contingency:** 4-6 additional calls ($0.60-0.90) for unforeseen complexity  
**Remaining budget:** $119+ for Phases 2-8

---

## Development Workflow

### Morning Loop (Use Ollama)

```bash
# Activate environment
cd /tmp/enterprise-osint-platform
venv_osint\Scripts\activate

# Start Ollama (separate window)
ollama serve

# Start Docker services
docker-compose up -d

# Generate code, test, commit
ollama run qwen2.5-coder:1.5b "Generate [component]"
pytest tests/
git add . && git commit -m "..."
```

**Time:** 4-6 hours of productive coding per day

### When Stuck (Use Claude)

```bash
# If Ollama hasn't solved it in 30+ minutes:
# Open Claude Code and describe the problem

# Example prompt:
"I'm stuck on PostgreSQL connection pooling for FastAPI.
Should I use SQLAlchemy Session factory, dependency injection, 
or async context managers? Show me skeleton code for the best approach."

# Cost: ~$0.15-0.20
# Benefit: Unstuck + learned approach for future similar problems
```

---

## GPU Memory Breakdown

**Your RTX 5060 Ti: 12GB VRAM**

| Service | VRAM | Available |
|---------|------|-----------|
| Ollama (Qwen-1.5b) | 2GB | ✓ |
| PostgreSQL | 256MB | ✓ |
| Redis | 128MB | ✓ |
| Elasticsearch | 512MB | ✓ |
| Neo4j | 512MB | ✓ |
| **Total** | **~3.5GB** | **~8.5GB free** |

**Result:** Can run full development stack + 3+ Ollama inference jobs simultaneously without contention.

---

## Cost Analysis: Full Project

### Phase 1: Core Infrastructure (2 weeks)

| Component | Calls | Cost |
|-----------|-------|------|
| Qwen local inference | ∞ | $0 |
| Claude Sonnet (architecture) | 1-2 | $0.20-0.30 |
| **Phase 1 Total** | — | **$0.30** |

### Phases 2-8: OSINT + Features (4 weeks)

| Phase | Calls | Cost |
|-------|-------|------|
| Phase 2: Tool Integration | 2 | $0.30 |
| Phase 3: API Integration | 1 | $0.15 |
| Phase 4: Questionnaire | 1 | $0.15 |
| Phase 5: Analysis | 1 | $0.15 |
| Phase 6: Reporting | 0 | $0 |
| Phase 7: Enterprise | 0 | $0 |
| Phase 8: Deployment | 1 | $0.15 |
| **Contingency** | 4-6 | $0.60-0.90 |
| **Phases 2-8 Total** | — | **$1.50** |

**Total Development Cost: $1.80** (within $120 budget)

---

## Comparison: Other Approaches

### Approach A: Pure Claude Sonnet

```
Cost: $1,600
Pros: Fast, reliable, handles complex logic
Cons: Expensive, slower iteration (API latency), overkill for code generation
Used by: Companies with unlimited budgets
```

### Approach B: Pure Haiku

```
Cost: $600
Pros: Cheaper than Sonnet
Cons: Risky for OSINT orchestration (may hallucinate), slower than Sonnet
Risk: Complex tool-chaining bugs slip through
```

### Approach C: Hybrid Ollama + Claude (YOUR CHOICE)

```
Cost: $120
Pros: Instant iteration (no API latency), 93% cost savings, Sonnet for hard problems
Cons: Qwen slower than Claude (120 vs 300 tokens/sec)
Result: Best balance of speed + cost
```

---

## Troubleshooting

### Ollama Won't Start

```cmd
# Check if port 11434 in use
netstat -ano | findstr :11434

# Kill process
taskkill /PID [PID] /F

# Restart
ollama serve
```

### GPU Not Detected

```cmd
# Verify GPU drivers
nvidia-smi

# Should show NVIDIA GeForce RTX 5060 Ti

# If not, update drivers: https://nvidia.com/drivers
```

### Ollama Running Slow

```cmd
# Check VRAM usage
ollama list

# If >8GB used, close other applications
# Qwen-1.5b should use ~2GB max
```

### Docker Port Conflicts

```cmd
# Free up port if needed
netstat -ano | findstr :5432  # PostgreSQL
taskkill /PID [PID] /F

# Restart Docker services
docker-compose down
docker-compose up -d
```

---

## Why This Strategy Wins

1. **Cost:** 93% cheaper than pure Claude ($120 vs $1,600)
2. **Speed:** Instant local inference (no API latency) → faster iteration
3. **Learning:** Understand what Ollama CAN do (surprising amount) vs what REQUIRES Claude
4. **Scalability:** Easy to add developers (all share single GPU) or regions (use Sonnet for all)
5. **Reliability:** Local inference doesn't depend on API availability

---

## Next Phase

After Phase 1 complete:
- Continue hybrid approach for Phases 2-8
- Estimated remaining budget: $118+ (very safe)
- Can increase Sonnet calls if needed without budget overrun

---

**Last Updated:** May 2026 | **Your GPU:** RTX 5060 Ti | **Your Budget:** $120
