# Task Cost Checklist - Apply Before Every Phase

**CRITICAL:** Always analyze task cost BEFORE starting implementation. This saves ~70% API costs per session.

---

## 4-Phase Workflow

### Phase 1: Analyze Task Complexity

Ask these questions:
- How many hours will this take? (simple = <4h, complex = >8h)
- How many dependencies? (dependencies = higher risk, more thinking needed)
- Is architecture clear? (unclear = needs Claude consultation)
- Will Qwen get stuck? (trial-and-error = needs Claude)

**Questions to ask:**
```
Is this task straightforward code generation?
  YES → Use Qwen (FREE)
  NO → Proceed to Phase 2

Do I know the exact architecture/approach?
  YES → Use Qwen (FREE)
  NO → Needs Claude consultation
```

---

### Phase 2: List Model Options

| Option | Model | Cost | Speed | Best For |
|--------|-------|------|-------|----------|
| **Option A** | Qwen2.5-coder-1.5B (local) | $0 | 120 tok/sec | Code generation, debugging, refactoring |
| **Option B** | Claude Sonnet API | $0.50-5.00 | 300 tok/sec | Complex architecture, stuck problems |
| **Option C** | Hybrid (Qwen + Sonnet) | $0.15-0.50 | Mixed | Most tasks (use Qwen, Sonnet for hard parts) |

**Select based on complexity:**
- Simple task (clear scope, straightforward code) → **Option A (Qwen only)**
- Complex task (architecture unclear, dependencies) → **Option B or C (Include Sonnet)**
- Medium task (some unknowns, mostly known) → **Option C (Hybrid)**

---

### Phase 3: Calculate Cost

**Qwen Cost:** $0 (runs locally on RTX 5060 Ti, 2GB VRAM)

**Claude Sonnet Cost:** $0.15-0.30 per strategic call
- Example: "Should I use [approach A] or [approach B]?" = 1 call
- Example: "Review this for security vulnerabilities" = 1 call
- Example: "How do I integrate 30 APIs?" = 1 call

**Total Budget for Enterprise OSINT Project:**
```
Phase 1: $0.30 (1-2 Sonnet calls)
Phase 2: $0.30 (2 Sonnet calls)
Phase 3: $0.15 (1 Sonnet call)
Phase 4: $0.15 (1 Sonnet call)
Phase 5: $0.15 (1 Sonnet call)
Phase 6: $0 (Qwen only)
Phase 7: $0 (Qwen only)
Phase 8: $0.15 (1 Sonnet call)
─────────────
TOTAL: $1.15 (within $120 budget)
```

**Decision Framework:**
```
Cost < $0.50?    → Go ahead, low risk
Cost $0.50-5?    → Ask user, get approval
Cost > $5?       → Reconsider approach, find cheaper way
Budget remaining? → Can afford? Proceed : Find alternative
```

---

### Phase 4: Inform User + Get Approval

**Template message to user:**
```
Task: [Phase X - Description]
Complexity: [Simple/Medium/Complex]
Recommended approach: [Option A/B/C]
Cost: [Qwen: $0 | Sonnet: $X.XX | Hybrid: $X.XX]
Time saved: [hours vs trial-and-error]
Total project cost remaining: $[amount]

Ready to proceed with [approach]? [YES/NO]
```

**Example for Phase 1 Core Infrastructure:**
```
Task: Phase 1 - Core Infrastructure (database schema, FastAPI, auth)
Complexity: Medium (known architecture, some integration unknowns)
Recommended: Hybrid (Qwen for code, Sonnet for JWT/auth design)
Cost: $0.30 (2 strategic Sonnet calls)
Time saved: ~4-6 hours vs figuring out JWT alone
Budget status: $120 → $119.70 remaining

Ready to start Phase 1 with Hybrid approach?
```

---

## Decision Tree

```
START: New Phase/Task
    ↓
Is this pure code generation? 
  YES → Use Qwen (QWEN_ONLY)
  NO ↓
Architecture clear?
  YES → Use Qwen (QWEN_ONLY)
  NO ↓
Will Qwen likely get stuck?
  YES → Use Hybrid (HYBRID)
  NO ↓
Is this a security/perf decision?
  YES → Use Hybrid (HYBRID)
  NO → Use Qwen (QWEN_ONLY)
    ↓
Calculate cost for chosen approach
    ↓
Is cost < remaining budget?
  YES → Proceed
  NO → Find cheaper alternative
    ↓
Inform user + get approval (if Sonnet involved)
    ↓
EXECUTE with chosen model(s)
```

---

## When to Use Each Model

### ✅ Use Qwen2.5-coder-1.5B (LOCAL, FREE)

- Generate FastAPI endpoints
- Create SQLAlchemy ORM models
- Write database migrations
- Debug Python errors
- Refactor code
- Write test cases
- Generate documentation
- Create configuration files
- Write bash/python scripts
- Fix type hints

**Cost:** $0 (runs on your GPU)
**Speed:** 120 tokens/sec on RTX 5060 Ti
**Quality:** 90% of tasks, excellent for code generation

---

### ✅ Use Claude Sonnet (API, ~$0.15-0.30 per call)

- "How should I architect the OSINT orchestrator?"
- "Should I use state machine or queue for tool scheduling?"
- "Review this JWT implementation for security holes"
- "How do I integrate 30+ APIs without rate limit issues?"
- "What's the best way to handle Neo4j relationship mapping?"
- "Performance optimization: this query is slow, how to fix?"
- "Stuck on [specific problem] for 30+ minutes, help?"

**Cost:** $0.15-0.30 per consultation
**Speed:** 300 tokens/sec (faster than Qwen)
**Quality:** Handles complex reasoning, architecture, security

---

### ✅ Use Hybrid (Qwen + Sonnet)

Start with Qwen:
1. "Generate FastAPI CRUD endpoints for investigations"
2. Code generated ✓
3. Run tests → some fail
4. "Fix these test failures" (Qwen, FREE)
5. Tests pass ✓
6. Performance is slow → stuck for 30+ min
7. **THEN:** Ask Sonnet "Optimize this database query"
8. Get optimization advice ($0.15)
9. Implement with Qwen (FREE)

**Total cost:** $0.15 (vs $3-5 if you asked Sonnet first)

---

## Anti-Patterns (DON'T DO)

❌ **Ask Sonnet immediately without trying Qwen first**
- Wastes budget
- Qwen could've solved it free

❌ **Keep asking Qwen when clearly stuck**
- Wasted time after 30+ minutes
- Should ask Sonnet for clarity

❌ **Use Sonnet for pure code generation**
- 10x more expensive than Qwen
- Same code quality for straightforward tasks

❌ **Forget to set budget and track spending**
- Overspend without realizing
- Miss optimization opportunities

---

## Budget Tracking Template

For each phase, fill this out:

```markdown
## Phase [X]: [Name]

Estimated Cost: $[amount]
Actual Cost: $[amount]
Qwen calls: [number] (FREE)
Sonnet calls: [number] × $0.15 = $[amount]
Hours worked: [hours]
Status: [In Progress / Complete]

Budget remaining: $120 - $[spent] = $[remaining]
```

---

## Real Example: Phase 1

**Phase 1: Core Infrastructure**

Planning:
- Task complexity: Medium (database schema known, JWT/auth needs review)
- Approach: Hybrid
- Estimated Sonnet calls: 2 (JWT architecture, RBAC design)
- Estimated cost: $0.30

Execution:
- Step 1-2: Project init + Database schema (Qwen, FREE) ✓
- Step 3-5: SQLAlchemy models, FastAPI, Config (Qwen, FREE) ✓
- Step 6: Authentication
  - JWT generation code (Qwen, FREE) ✓
  - "Is this JWT implementation secure? Should I add..." (Sonnet, $0.15) ✓
  - Fix based on feedback (Qwen, FREE) ✓
- Step 7-11: CRUD, testing, docs (Qwen, FREE) ✓

**Actual cost: $0.15**
**Budget remaining: $120 - $0.15 = $119.85**

---

## Success Metrics

✓ Cost per phase < budgeted amount
✓ No Sonnet calls wasted on questions Qwen could answer
✓ No excessive Qwen loop (>30 min stuck = ask Sonnet)
✓ All work tracked and committed to git
✓ Documentation complete
✓ Tests passing

---

## Questions to Ask Before Each Phase

1. **Clear scope?** "I need to implement [X], which includes [A, B, C]"
2. **Known architecture?** "I'll use FastAPI + SQLAlchemy + PostgreSQL"
3. **Dependency clarity?** "Phase 1 blocks Phase 2, which blocks Phase 3"
4. **Success criteria?** "Phase complete when [X, Y, Z] working"
5. **Risk assessment?** "Main risks: [integration complexity, API limits]"
6. **Model choice?** "Start with Qwen, escalate to Sonnet if stuck >30min"

---

**Use this checklist BEFORE starting each phase. Saves time + money. 🚀**

**Last Updated:** May 2026 | **Project Budget:** $120 | **Status:** 4-6 week implementation
