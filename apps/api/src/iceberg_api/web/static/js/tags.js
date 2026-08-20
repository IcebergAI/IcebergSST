/* Alpine component registry — the CSP-safe half of the interaction layer.
 *
 * The page loads the @alpinejs/csp build, which interprets directive
 * expressions instead of compiling them with `new Function()`. That is what
 * lets the Content-Security-Policy stay at `script-src 'self'` with no
 * 'unsafe-eval' and no 'unsafe-inline' (see web/security.py). The trade is that
 * behaviour cannot live in the markup:
 *
 *   - `x-data="{ open: false }"`            fine (data only)
 *   - `x-data="{ toggle() { … } }"`         NOT parseable — methods must be here
 *   - `@click="open = !open"`, `x-text="n"` fine (the interpreter handles these)
 *
 * So every component is registered below with Alpine.data(), and the markup
 * names it: `x-data="confirmAction"`.
 *
 * This file must load BEFORE the Alpine bundle. Alpine dispatches `alpine:init`
 * during its own deferred startup; a listener registered after that has already
 * fired never runs, and every x-data on the page silently fails to resolve.
 * base.html orders the two <script defer> tags accordingly.
 *
 * SERVER DATA arrives through a <script type="application/json"> island inside
 * the component's own root element, read by readIsland() below. Never through an
 * x-data attribute: the CSP expression parser does not decode \uXXXX escapes,
 * and Jinja's |tojson escapes `< > & '` that way, so a page title containing an
 * apostrophe would arrive corrupted. A JSON island goes through JSON.parse,
 * which decodes them correctly. (A `type` the browser does not recognise as
 * executable is a data block, not a script, so the CSP does not apply to it.)
 */

/**
 * Read this component's JSON payload: the first application/json island inside
 * its root element. Returns {} when there is none, so a component with no server
 * data needs no special case.
 */
function readIsland(root) {
  const el = root && root.querySelector('script[type="application/json"]');
  if (!el) return {};
  try {
    return JSON.parse(el.textContent);
  } catch (_) {
    return {};
  }
}

document.addEventListener('alpine:init', () => {
  /* ----------------------------------------------------------------------- *
   * confirmAction — a two-step guard on a destructive control.
   *
   * `window.confirm` is the usual answer and is the wrong one here: it is a
   * modal that steals focus, cannot be styled, and reads identically whether it
   * is about to delete one suppression or every finding behind it. Arming the
   * button in place keeps the object's name on screen while the analyst decides.
   *
   *   <div x-data="confirmAction">
   *     <button x-show="!armed" @click="arm()" class="btn btn--danger">Delete</button>
   *     <span x-show="armed" x-cloak>
   *       <button hx-delete="/x/1" class="btn btn--danger btn--sm">Confirm</button>
   *       <button @click="disarm()" class="btn btn--quiet btn--sm">Cancel</button>
   *     </span>
   *   </div>
   * ----------------------------------------------------------------------- */
  Alpine.data('confirmAction', () => ({
    armed: false,
    timer: null,
    arm() {
      this.armed = true;
      // Re-hides itself, so a half-pressed delete left open in a background tab
      // is not still armed when somebody comes back to it.
      clearTimeout(this.timer);
      this.timer = setTimeout(() => { this.armed = false; }, 6000);
    },
    disarm() {
      clearTimeout(this.timer);
      this.armed = false;
    },
    destroy() {
      clearTimeout(this.timer);
    },
  }));

  /* ----------------------------------------------------------------------- *
   * copyable — copy a shown-once credential.
   *
   * Used for the engine token, which the API returns exactly once and cannot
   * show again. The button reports what happened, because an operator who
   * assumes a silent copy worked has lost the credential.
   * ----------------------------------------------------------------------- */
  Alpine.data('copyable', () => ({
    state: 'idle',
    async copy() {
      const source = this.$refs.value;
      if (!source) return;
      try {
        await navigator.clipboard.writeText(source.textContent.trim());
        this.state = 'copied';
      } catch (_) {
        // Insecure origin, or the permission was refused. Select it instead so
        // ⌘C still works, and say so.
        this.state = 'failed';
        const range = document.createRange();
        range.selectNodeContents(source);
        const selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
      }
      setTimeout(() => { this.state = 'idle'; }, 2500);
    },
  }));

  /* ----------------------------------------------------------------------- *
   * disclosure — a labelled show/hide region (inline create forms).
   *
   * `open` starts from data-open on the root, so a form the server wants shown
   * (a validation failure being re-rendered) is open on arrival rather than
   * flashing shut and making the analyst hunt for their own input.
   * ----------------------------------------------------------------------- */
  Alpine.data('disclosure', () => ({
    open: false,
    init() {
      this.open = this.$el.dataset.open === 'true';
    },
    toggle() {
      this.open = !this.open;
    },
  }));

  /* ----------------------------------------------------------------------- *
   * sourceForm — the create/edit form for a source (#55).
   *
   * Three jobs the server cannot do without a round trip:
   *   - the scope list is a set of chips, added and removed before submit;
   *   - Cloud is selected by *supplying an email* (Basic email:token) and
   *     Server/DC by omitting it, which is a rule nobody should have to know —
   *     the select makes it explicit and the hidden email field carries the
   *     actual API contract;
   *   - `type` toggles which scope block is shown (#144, #196). All three stay in
   *     the DOM, so switching back does not discard what was already typed.
   *
   * The scope keys go to the server as repeated `spaces`/`projects`/`roots`/
   * `include`/`exclude` inputs rather than JSON: the route assembles the
   * connection blob, so there is exactly one place that knows the shape and the
   * API's validation is the only validation that counts. The blocks that are
   * hidden still post their inputs; the route reads only the ones belonging to
   * the source's type.
   *
   * A file share is the odd one out and stays odd on purpose: no base URL, no
   * deployment choice, and **no credential**, because the mount carries all three
   * (#145). Its chips are paths rather than keys, so they are not upper-cased.
   *
   * The Cloud-vs-DC email rule is identical for both products, which is the
   * whole point of sharing one credential type across connectors.
   * ----------------------------------------------------------------------- */
  Alpine.data('sourceForm', () => ({
    type: 'confluence',
    deployment: 'cloud',
    email: '',
    spaces: [],
    spaceDraft: '',
    projects: [],
    projectDraft: '',
    roots: [],
    rootDraft: '',
    include: [],
    includeDraft: '',
    exclude: [],
    excludeDraft: '',
    maxFileBytes: '',
    rotating: false,
    hasCredential: false,
    init() {
      const data = readIsland(this.$el);
      this.type = typeof data.type === 'string' ? data.type : 'confluence';
      this.spaces = Array.isArray(data.spaces) ? data.spaces.slice() : [];
      this.projects = Array.isArray(data.projects) ? data.projects.slice() : [];
      this.roots = Array.isArray(data.roots) ? data.roots.slice() : [];
      this.include = Array.isArray(data.include) ? data.include.slice() : [];
      this.exclude = Array.isArray(data.exclude) ? data.exclude.slice() : [];
      this.email = typeof data.email === 'string' ? data.email : '';
      this.deployment = this.email ? 'cloud' : (data.isNew ? 'cloud' : 'server');
      this.hasCredential = data.hasCredential === true;
      // A saved source keeps its credential unless the analyst asks to replace
      // it; a new one always needs one.
      this.rotating = !this.hasCredential;
    },
    get emailValue() {
      // Server/DC authenticates with a bearer PAT and must send no email at all;
      // an empty string is what the API reads as "omitted".
      return this.deployment === 'cloud' ? this.email : '';
    },
    addSpace() {
      const key = this.spaceDraft.trim().toUpperCase();
      if (key && !this.spaces.includes(key)) this.spaces.push(key);
      this.spaceDraft = '';
    },
    removeSpace(key) {
      this.spaces = this.spaces.filter((item) => item !== key);
    },
    addProject() {
      const key = this.projectDraft.trim().toUpperCase();
      if (key && !this.projects.includes(key)) this.projects.push(key);
      this.projectDraft = '';
    },
    removeProject(key) {
      this.projects = this.projects.filter((item) => item !== key);
    },
    // Paths and globs, not keys: case is significant on the filesystems these
    // describe, so unlike a space or project key nothing here is upper-cased. A
    // leading slash is trimmed because a root is relative to the mount and the
    // API answers 422 for one — better to take the obvious meaning than to teach
    // the rule with an error.
    addRoot() {
      this.pushPath('roots', 'rootDraft');
    },
    removeRoot(path) {
      this.roots = this.roots.filter((item) => item !== path);
    },
    addInclude() {
      this.pushPath('include', 'includeDraft');
    },
    removeInclude(glob) {
      this.include = this.include.filter((item) => item !== glob);
    },
    addExclude() {
      this.pushPath('exclude', 'excludeDraft');
    },
    removeExclude(glob) {
      this.exclude = this.exclude.filter((item) => item !== glob);
    },
    pushPath(list, draft) {
      const value = this[draft].trim().replace(/^\/+/, '');
      if (value && !this[list].includes(value)) this[list].push(value);
      this[draft] = '';
    },
    get maxFileSummary() {
      const bytes = Number.parseInt(this.maxFileBytes, 10);
      if (!Number.isFinite(bytes) || bytes < 1) return 'not a size';
      const mib = bytes / (1024 * 1024);
      // Whole MiB is the common case and reads better without a decimal point.
      return `${mib >= 1 ? `${Number.isInteger(mib) ? mib : mib.toFixed(1)} MiB` : `${bytes} bytes`}`;
    },
    startRotation() {
      this.rotating = true;
    },
    cancelRotation() {
      this.rotating = false;
    },
  }));

  /* ----------------------------------------------------------------------- *
   * triageForm — the finding triage panel (#57).
   *
   * The finding state machine allows open → judgement and judgement → open, but
   * never one judgement straight to another: relabelling in place would leave a
   * trail reading "it was always this". The API answers 409 either way; this
   * disables the options that would earn one, so the rule is visible before the
   * click rather than after it.
   * ----------------------------------------------------------------------- */
  Alpine.data('triageForm', () => ({
    current: 'open',
    next: 'open',
    comment: '',
    init() {
      const data = readIsland(this.$el);
      this.current = data.state || 'open';
      this.next = this.current;
    },
    allowed(state) {
      if (state === this.current) return true;
      // From open, any judgement. From a judgement, only back to open.
      return this.current === 'open' ? state !== 'open' : state === 'open';
    },
    get unchanged() {
      return this.next === this.current && this.comment.trim() === '';
    },
    get willReopen() {
      return this.current !== 'open' && this.next === 'open';
    },
  }));

  /* ----------------------------------------------------------------------- *
   * channelForm — the notification-channel create form (#72).
   *
   * Which config fields exist depends entirely on the channel type, and the two
   * shapes share nothing. Switching the type swaps the fieldset rather than
   * leaving an email list visible on a webhook.
   *
   * There is no edit flow: a channel is created and deleted, so this carries no
   * "keep the stored secret" state the way sourceForm does.
   * ----------------------------------------------------------------------- */
  Alpine.data('channelForm', () => ({
    type: 'webhook',
    init() {
      const data = readIsland(this.$el);
      this.type = data.type || 'webhook';
    },
  }));

  /* ----------------------------------------------------------------------- *
   * cronField — the schedule expression, with the four cadences people
   * actually ask for. Typing a custom expression still works; the API validates
   * it either way, and an invalid one comes back as a 422 on the field.
   * ----------------------------------------------------------------------- */
  Alpine.data('cronField', () => ({
    cron: '0 3 * * *',
    init() {
      const data = readIsland(this.$el);
      if (typeof data.cron === 'string' && data.cron) this.cron = data.cron;
    },
    use(expression) {
      this.cron = expression;
    },
  }));
});
