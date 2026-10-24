/**
 * Prompt injection pattern library.
 *
 * This is the single source of truth for heuristic injection detection across
 * the CLI evaluator, the gateway input sanitizer and the shield runtime
 * analyzer. Every pattern is tuned against two corpora in
 * `__tests__/injection.corpus.test.ts`: a set of attacks that must be caught
 * and a set of ordinary user messages that must not be flagged.
 *
 * Design rules for patterns:
 *
 * 1. Generic verbs ("act as", "pretend", "new", "system") are never enough on
 *    their own. A pattern needs the verb plus an attack-specific object
 *    (an AI identity, a safety term, a prompt term, a delimiter).
 * 2. Severity reflects how often the phrase appears in benign text:
 *    - critical: essentially never benign ("ignore all previous instructions")
 *    - high: very rarely benign ("what is your system prompt")
 *    - medium: sometimes benign, worth logging ("enable developer mode")
 *    - low: often benign, only for high sensitivity audits ("bypass")
 * 3. Whitespace between words is written as a single space in the source and
 *    expanded to `\s+` so tabs and newlines cannot evade a pattern.
 */

import type {
  Confidence,
  InjectionCategory,
  InjectionMatch,
  InjectionPattern,
  Sensitivity,
  Severity,
} from './types';

// =============================================================================
// Helpers
// =============================================================================

/**
 * Build a case-insensitive global regex from a readable source string.
 * Single spaces become `\s+` so that "ignore all previous" also matches
 * "ignore\tall\nprevious".
 */
function rx(source: string, flags = 'gi'): RegExp {
  return new RegExp(source.replace(/ /g, '\\s+'), flags);
}

function def(
  name: string,
  category: InjectionCategory,
  severity: Severity,
  description: string,
  pattern: RegExp
): InjectionPattern {
  return { name, category, severity, description, pattern };
}

// Reusable fragments
const SAFETY_NOUN =
  '(?:filters?|filtering|guidelines?|rules?|measures?|restrictions?|guardrails?|protocols?|constraints?|mode|settings?|checks?|policies|policy|training|alignment|mechanisms?|controls?|limits?|limitations?|boundaries|safeguards?)';
const SAFETY_ADJ = '(?:content|safety|ethical|ethics|moral|security|usage|harm)';
const INSTRUCTION_NOUN =
  '(?:instructions?|prompts?|rules?|guidelines?|directions?|directives?|constraints?|programming|guardrails|policies|policy|training|commands?|orders?)';
const INSTRUCTION_ADJ =
  '(?:all|any|every|the|these|those|your|my|our|previous|prior|above|earlier|preceding|original|initial|existing|system|safety|ethical|current|standard|default|usual|normal)';
const AI_IDENTITY =
  '(?:ai|a\\.i\\.|chatbot|language model|llm|gpt[-\\w]*|(?:evil|dark|bad|anti|dan)[- ]?gpt|hacker|villain|criminal|chatgpt|claude|gemini|copilot|(?:different|new|other|another|alternative|rival|rogue|free|unlocked) (?:ai|model|assistant|bot|chatbot|system|entity|persona|version|personality))';
const BAD_QUALIFIER =
  '(?:unrestricted|unfiltered|uncensored|unlimited|unbound|unchained|unshackled|evil|malicious|unethical|immoral|amoral|rogue|jailbroken|villainous|dark|lawless|unaligned|uninhibited|unmoderated|no-?filter)';

// =============================================================================
// Pattern Library
// =============================================================================

export const INJECTION_PATTERNS: readonly InjectionPattern[] = [
  // ---------------------------------------------------------------------------
  // instruction_override
  // ---------------------------------------------------------------------------
  def(
    'ignore_instructions',
    'instruction_override',
    'critical',
    'Direct instruction override attempt',
    rx(
      `\\b(?:ignor(?:e|es|ing)|disregard(?:s|ing)?|skip|overlook|set aside|throw away|discard|abandon) (?:${INSTRUCTION_ADJ} )*${INSTRUCTION_NOUN}\\b`
    )
  ),
  def(
    'forget_instructions',
    'instruction_override',
    'critical',
    'Instruction erasure attempt',
    rx(
      `\\bforget (?:${INSTRUCTION_ADJ} )*${INSTRUCTION_NOUN}\\b|\\bforget (?:everything|all|what|anything) (?:(?:that |which )?(?:you (?:were|have been|'ve been|are|got) (?:told|taught|instructed|given|programmed|trained)|i (?:said|told you|wrote)|(?:came|was said|was written) (?:before|above|previously|earlier))|before|above|previous(?:ly)?|so far|up to now)\\b|\\bforget everything\\b`
    )
  ),
  def(
    'override_instructions',
    'instruction_override',
    'critical',
    'Instruction override attempt',
    rx(
      `\\b(?:override|overwrite|overrule|replace|cancel|revoke|suspend|nullify|void) (?:${INSTRUCTION_ADJ} )*(?:system prompt|${INSTRUCTION_NOUN}|safety|programming|personality|persona|identity)\\b`
    )
  ),
  def(
    'override_safety',
    'instruction_override',
    'critical',
    'Safety control override attempt',
    rx(
      `\\b(?:override|overwrite|disable|turn off|switch off|deactivate|remove|bypass|circumvent|suspend|lift|drop|ignor(?:e|es|ing)|skip|disregard|evade|defeat) (?:all |any |your |the |these |those |every |of |its |their )*${SAFETY_ADJ} ${SAFETY_NOUN}\\b|\\b(?:disable|turn off|switch off|deactivate|remove|bypass|drop|lift|ignor(?:e|es|ing)|suspend) (?:all (?:of )?)?your (?:own )?(?:filters?|filtering|restrictions?|guardrails?|safeguards?|limitations?|limits|censorship|programming|safety|alignment|training|rules|guidelines|constraints)\\b`
    )
  ),
  def(
    'new_instructions',
    'instruction_override',
    'high',
    'Replacement instructions announced',
    rx(
      `\\b(?:new|real|actual|true|updated|revised|following|secret|hidden|correct|primary|final) (?:system )?(?:instructions?|prompt|task|rules?|directives?|purpose|parameters|settings|config(?:uration)?|objective|mission|orders?|commands?)\\s*[:=]|\\byour new (?:purpose|role|identity|persona|personality|name|instructions?|objective|mission|directives?|task|job|function) (?:is|are|will be|shall be|:)`
    )
  ),
  def(
    'system_prompt_override',
    'instruction_override',
    'high',
    'Fake system message',
    rx(
      `(?:^|[\\s\\[])system\\s*\\]?\\s*[:=]\\s*(?:you are|you're|your (?:new )?(?:instructions?|role|purpose|task))`
    )
  ),
  def(
    'instructions_cancelled',
    'instruction_override',
    'high',
    'Instruction cancellation claim',
    rx(
      `\\b(?:previous|prior|above|earlier|old|original|your|the|all|those|these) (?:system )?(?:instructions?|rules?|prompts?|guidelines?|directives?|constraints?) (?:are|is|were|have been|has been) (?:now |hereby |all |officially |henceforth )?(?:cancell?ed|void|null|invalid|revoked|suspended|obsolete|lifted|rescinded|terminated|no longer (?:valid|in effect|apply|applicable|relevant))\\b`
    )
  ),
  def(
    'nevermind_instructions',
    'instruction_override',
    'high',
    'Instruction dismissal attempt',
    rx(
      `\\bnever\\s*mind (?:all |about )?(?:that|this|everything|the above|what (?:i|you) (?:said|were told|just said)|(?:the |your )?(?:previous|prior|earlier) (?:instructions?|message|prompt|rules))\\b`
    )
  ),
  def(
    'stop_being_ai',
    'instruction_override',
    'critical',
    'Identity override attempt',
    rx(
      `\\bstop (?:being|acting (?:as|like)|behaving (?:as|like)|pretending to be) (?:an? |the )?(?:ai|a\\.i\\.|assistant|chatbot|bot|language model|llm|helpful|responsible|safe|ethical)\\b|\\byou are no longer (?:an? |the )?(?:ai|assistant|chatbot|bot|language model|bound|restricted|limited|required|obligated)\\b`
    )
  ),

  // ---------------------------------------------------------------------------
  // role_manipulation
  // ---------------------------------------------------------------------------
  def(
    'jailbreak',
    'role_manipulation',
    'critical',
    'Explicit jailbreak attempt',
    rx(
      `\\bjailbreak(?:ing|s)? (?:mode|prompt|you|yourself|protocol|activated|enabled|the (?:ai|model|assistant|system|bot|chatbot))\\b|\\b(?:enable|activate|enter|engage|turn on|initiate|start|begin|unlock) (?:the |a )?jailbreak\\b|\\bjailbroken\\b|\\bjailbreak[:=]`
    )
  ),
  def(
    'jailbreak_dan',
    'role_manipulation',
    'critical',
    'Known jailbreak technique (DAN)',
    // Case sensitive on purpose: "DAN" the persona, not "Dan" the name.
    rx(
      `\\b(?:as|be|become|now|am|named|called|mode|activate|enable|enter|into|is|like|to|play|roleplay|simulate)\\s+DAN\\b|\\bDAN\\s+(?:mode|prompt|jailbreak|which|stands|persona|version|protocol|here|is an? )|\\bDAN\\s*[-\\u2013\\u2014:(]|\\bDAN\\.`,
      'g'
    )
  ),
  def(
    'jailbreak_dan',
    'role_manipulation',
    'critical',
    'Known jailbreak technique (DAN)',
    rx(`\\bdo anything now\\b`)
  ),
  def(
    'developer_mode',
    'privilege_escalation',
    'medium',
    'Special mode activation',
    rx(
      `\\b(?:enable|activate|enter|engage|turn on|switch to|initiate|unlock|start|open|access|begin|go into|put yourself in(?:to)?) (?:the |a |your )?(?:developer|dev|debug|debugging|maintenance|diagnostic|test(?:ing)?|god|sandbox|verbose|raw|safe|secret|hidden|special) mode\\b|\\b(?:developer|dev|debug|maintenance|god|diagnostic) mode (?:enabled|activated|on|engaged|unlocked|is now (?:on|active|enabled))\\b|\\byou are now in (?:developer|dev|debug|maintenance|god|diagnostic|test) mode\\b`
    )
  ),
  def(
    'privileged_mode',
    'privilege_escalation',
    'high',
    'Privileged or unrestricted mode activation',
    rx(
      `\\b(?:enable|activate|enter|engage|turn on|switch to|initiate|unlock|start|grant|give me|put yourself in(?:to)?|you are now in|operate in|run in|respond in) (?:the |a |your |an )?(?:admin(?:istrator)?|root|sudo|superuser|super user|unrestricted|unfiltered|uncensored|unlimited|unchained|jailbreak|dan|evil|free|freedom|no[- ]?filter|no[- ]?rules|anything[- ]?goes|opposite|chaos|anarchy|omega|alpha|developer override|override) mode\\b|\\b(?:admin(?:istrator)?|root|superuser|unrestricted|unfiltered|uncensored|unlimited|override|freedom|opposite) mode (?:enabled|activated|on|engaged|unlocked|is now (?:on|active|enabled))\\b|\\bunrestricted (?:mode|access|ai|version|assistant|model|output|responses?)\\b`
    )
  ),
  def(
    'no_restrictions',
    'role_manipulation',
    'high',
    'Restriction removal request',
    rx(
      `\\b(?:you are|you're|you will be|you'll be|you must be|you should be|be|become|act|acting|pretend|roleplay|role-play|respond|answer|reply|operate|behave|function|exist|speak|talk|ai|a\\.i\\.|assistant|chatbot|bot|model|mode|conversation|session|persona|entity|version|gpt|character|personality|yourself|itself)\\b[^.!?\\n]{0,60}?\\b(?:no|without(?: any| all)?|free (?:of|from)|zero|devoid of|unbound by|not bound by|regardless of|lacking) (?:(?:any|all|the|your|its|ethical|moral|content|safety|usage) )*(?:restrictions?|limits?|limitations?|boundaries|filters?|filtering|censorship|rules|guardrails?|safeguards?|safety(?: (?:measures|guidelines|guardrails|filters|rules|protocols|training|constraints))?|ethical (?:boundaries|guidelines|limits|constraints|rules|considerations|concerns)|ethics|morals?|morality|content polic(?:y|ies)|moderation|constraints|regard for (?:safety|ethics|rules)|conscience|oversight|supervision|programming|guidelines)\\b`
    )
  ),
  def(
    'roleplay_identity',
    'role_manipulation',
    'high',
    'Role play as an unrestricted or alternate AI',
    rx(
      `\\b(?:pretend|act|behave|respond|answer|reply|talk|speak|roleplay|role-play|simulate|imagine|assume|adopt|take on|play|operate|function|you are now|you're now|you are|you're|from now on you are|from now on you're|become|transform into|turn into|you will be|you'll be|you must be|you should be|be) (?:to be |as if you are |as if you're |as if you were |as though you are |like you are |like you're |as |being |the role of |the persona of |you are |you're |that you are |that you're |yourself as |in the role of |now )?(?:an? |the |my |our )?(?:(?:new |different |other |another |unrestricted |unfiltered |uncensored |evil |malicious |unethical |immoral |amoral |rogue |jailbroken |free |hypothetical |fictional |alternate |alternative |powerful |all-powerful |omniscient |unaligned |villainous |dark |lawless |uninhibited |unmoderated )*(?:${AI_IDENTITY})|${BAD_QUALIFIER} (?:\\w+[- ]?){0,2}?(?:ai|a\\.i\\.|assistant|chatbot|bot|model|version|entity|persona|character|personality|system|intelligence|being|mode|self|one|gpt[-\\w]*|chatgpt|claude|gemini|alter ego|twin|clone|copy|variant|\\w+))\\b`
    )
  ),
  def(
    'persona_adoption',
    'role_manipulation',
    'high',
    'Persona adoption attempt',
    rx(
      `\\b(?:play(?:ing)? the (?:role|part|character) of|adopt(?:ing)? the (?:persona|personality|identity|role|character) of|take on the (?:role|persona|identity|character) of|assume the (?:role|identity|persona|character) of|in the role of|simulate being|simulating|embody|embodying|channel|channeling|personify) (?:an? |the |my )?(?:\\w+[- ]?){0,3}?(?:ai|a\\.i\\.|assistant|chatbot|bot|villain|hacker|criminal|${BAD_QUALIFIER}|different|rogue|entity|model|gpt|chatgpt|claude|gemini|dan)\\b`
    )
  ),
  def(
    'from_now_on',
    'role_manipulation',
    'high',
    'Persistent behaviour change',
    rx(
      `\\bfrom (?:now|this (?:point|moment|message)) on(?:wards?)?,? (?:you (?:will|must|should|are going to|shall|are|'re|have to|need to|ought to) (?:always |only |now )?(?:respond|answer|reply|act|behave|speak|be|pretend|roleplay|operate|ignore|forget|disregard|refuse|never|no longer)|(?:always |only )?(?:respond|answer|reply|act|behave|speak|operate|ignore|forget|disregard)) (?:as|like|without|with no|all|any|your|every|the|in character|in the role|to|as if)\\b`
    )
  ),

  // ---------------------------------------------------------------------------
  // prompt_extraction
  // ---------------------------------------------------------------------------
  def(
    'prompt_extraction',
    'prompt_extraction',
    'high',
    'System prompt extraction attempt',
    rx(
      `\\b(?:show|tell|reveal|display|print|output|repeat|share|give|leak|dump|expose|disclose|recite|echo|write out|paste|copy|spell out|quote|read(?: back| out)?|send|return|provide|list|state|type out|type|produce|regurgitate|reproduce|restate|rewrite|translate)(?: me| us| back| out| it)?(?: all| exactly| verbatim| word for word| in full)?(?: of)? (?:(?:the |this |that |all |any |every |each |both )(?:exact |full |entire |complete |verbatim |whole |original |initial |hidden |secret |confidential |internal |underlying |core |base |real |true |above |previous |earlier |first |preceding )*(?:system (?:prompt|message|instructions?|directives?|rules|config(?:uration)?)|initial (?:prompt|message|instructions?)|pre-?prompt|developer (?:message|instructions?|prompt)|hidden (?:prompt|instructions?|rules|text|message)|secret (?:prompt|instructions?|rules)|original (?:prompt|instructions?)|instructions? (?:you were|you've been|you have been|that you were) given)|(?:your|its) (?:own |current |exact |full |entire |complete |verbatim |whole |actual |precise |literal |raw |unedited )*(?:(?:original |initial |hidden |secret |confidential |internal |underlying |core |base |real |true |system |developer |custom |pre-?prompt )+(?:prompt|prompts|message|instructions?|directives?|rules|guidelines|text|config(?:uration)?)|system prompt|system message|system instructions?|programming|pre-?prompt|hidden (?:text|message|prompt|instructions?)|developer (?:message|instructions?|prompt)|source (?:code|prompt)|training (?:prompt|instructions)|operating instructions|meta ?prompt|context window|conversation history))\\b`
    )
  ),
  def(
    'prompt_extraction_generic',
    'prompt_extraction',
    'medium',
    'Request to disclose instructions',
    rx(
      `\\b(?:show|tell|reveal|display|print|output|repeat|share|give|leak|dump|expose|disclose|recite|echo|write out|paste|copy|spell out|quote|read(?: back| out)?|send|return|provide|list|state|type out|produce|reproduce|restate)(?: me| us| back| out| it)?(?: all| exactly| verbatim| word for word| in full)?(?: of)? (?:your|its) (?:own |current |exact |full |entire |complete |verbatim |whole |actual |precise |literal |raw |unedited )*(?:prompt|prompts|instructions?|directives?|rules and guidelines|guidelines and rules)\\b|\\bwhat(?:'s| is| are| was| were)(?: exactly| precisely| actually| really)? (?:in |inside |written in |contained in )?(?:your|its) (?:own |current |exact |full |entire |complete |actual )*(?:prompt|prompts|instructions?|directives?|rules and guidelines)\\b`
    )
  ),
  def(
    'prompt_extraction_question',
    'prompt_extraction',
    'high',
    'System prompt extraction question',
    rx(
      `\\bwhat(?:'s| is| are| was| were| does| do)(?: exactly| precisely| actually| really)? (?:in |inside |written in |contained in |included in |at the (?:top|start|beginning) of )?(?:(?:your|its) (?:exact |full |entire |complete |current |actual )*(?:(?:original |initial |hidden |secret |confidential |internal |real |true |system |developer |pre-?prompt )+(?:prompt|prompts|message|instructions?|directives?|rules|guidelines|text)|system prompt|system message|system instructions?|programming|pre-?prompt|hidden (?:text|message|prompt|instructions?)|developer (?:message|instructions?|prompt)|meta ?prompt|operating instructions)|(?:the|this|that) (?:exact |full |entire |complete |original |initial |hidden |secret |confidential |internal |real |true |current |actual )*(?:system (?:prompt|message|instructions?)|initial (?:prompt|message)|pre-?prompt|developer (?:message|instructions?|prompt)|hidden (?:prompt|instructions?|rules)|prompt (?:you were|you've been|you have been) given|instructions? (?:you were|you've been|you have been) given))\\b`
    )
  ),
  def(
    'told_instructions',
    'prompt_extraction',
    'high',
    'Instruction disclosure question',
    rx(
      `\\b(?:rules?|instructions?|guidelines?|prompts?|directives?|constraints?|restrictions?|guardrails|orders?|commands?|tasks?|goals?|objectives?|guidance|programming) (?:that |which )?(?:you (?:were|have been|'ve been|are|got|had been)|were) (?:given|told|instructed|programmed|trained|provided|configured|set up|assigned|handed|issued|fed)\\b|\\bwhat (?:were|are|have|was|did) you (?:(?:originally |initially |first |actually |really |secretly |specifically )?(?:told|instructed|programmed|trained|configured|asked|ordered|commanded|designed|built|made|taught|set up|prompted|primed|fed))(?: to (?:do|say|follow|be|avoid|hide|never)| by| with| not| about| at the (?:start|beginning))?\\b|\\bwhat did (?:the |your |my )?(?:developers?|creators?|programmers?|engineers?|makers?|designers?|owners?|operators?|admins?|administrators?|company|openai|anthropic|google|microsoft|meta) (?:tell|instruct|program|give|ask|order|command|teach|configure|prompt|say to|write (?:to|for)) you\\b|\\bhow (?:were|have) you (?:been )?(?:instructed|programmed|configured|prompted|primed|told|set up)(?: to (?:behave|act|respond|answer))?\\b`
    )
  ),
  def(
    'repeat_above',
    'prompt_extraction',
    'high',
    'Context dump request',
    rx(
      `\\b(?:repeat|print|output|echo|recite|reproduce|write|copy|paste|display|show|return|dump|regurgitate|give me|tell me) (?:back |out |to me |me |everything |all )?(?:(?:all (?:of )?)?(?:the )?(?:text|words|content|messages?|tokens?|characters?|lines?) (?:above|before|preceding|prior to|that came before|so far|up to (?:this|now|here))|everything (?:above|before|prior|preceding|that came before|so far|up to (?:this|now|here)|you (?:were told|have been told|have seen|know|can see|were given)|in (?:your|the) (?:context|memory|prompt|instructions))|all (?:of )?(?:your|the) (?:previous|prior|earlier|above|preceding) (?:text|messages?|content|instructions?|prompts?)|what (?:came|was said|was written|appeared|you were told|you saw) (?:before|above|previously|earlier|first|at the (?:start|beginning|top))|the (?:conversation|message|prompt|text|instructions?) (?:above|before|so far|up to (?:this|now|here))|everything (?:from|since) the (?:start|beginning|top)|(?:the )?(?:first|initial|original|very first) (?:message|prompt|instructions?|text) (?:you (?:received|got|saw|were given)|in (?:this|the|our) (?:conversation|chat|session|context))|(?:the )?(?:first|initial|original|very first) (?:prompt|instructions?|system message))\\b`
    )
  ),
  def(
    'prompt_extraction_soft',
    'prompt_extraction',
    'medium',
    'Configuration disclosure request',
    rx(
      `\\b(?:show|tell|reveal|display|print|output|repeat|share|give|describe|explain|list|summarize|outline|detail|enumerate|disclose|expose|dump|export|write out|state|recite)(?: me| us| back| out)? (?:all |any |every |each )?(?:of )?(?:your|its) (?:own |current |internal |full |complete |exact |entire |underlying |hidden |secret |confidential |default |original |initial |core |base )*(?:rules|guidelines|configuration|config|settings|parameters|constraints|restrictions|limitations|directives|policies|instruction set|programming|objectives|goals|persona|personality|guardrails|boundaries|operating (?:rules|parameters|guidelines|principles)|behavioral (?:rules|guidelines)|secret|secrets|hidden (?:rules|settings|features|abilities|commands)|training|setup|backstory|character sheet|identity|true (?:self|identity|nature|purpose))\\b`
    )
  ),
  def(
    'hidden_instructions',
    'obfuscation',
    'medium',
    'Reference to hidden or secret instructions',
    rx(
      `\\b(?:hidden|secret|concealed|confidential|internal|invisible|covert|private|unspoken|embedded|encoded|obscured) (?:system |developer |admin |special )?(?:instructions?|prompt|prompts|rules|message|messages|text|directives?|commands?|orders?|agenda|objective|goal|task|mission)\\b`
    )
  ),

  // ---------------------------------------------------------------------------
  // delimiter_injection
  // ---------------------------------------------------------------------------
  def(
    'chat_delimiter_bracket',
    'delimiter_injection',
    'high',
    'Chat delimiter injection',
    rx(
      `\\[\\s*\\/?\\s*(?:system|assistant|user|human|ai|inst|sys|instructions?|prompt|admin|developer|dev|root|override|end|begin|start|context|tool|function|response|output|input)\\s*\\]`
    )
  ),
  def(
    'chat_delimiter_xml',
    'delimiter_injection',
    'high',
    'Chat delimiter injection',
    rx(
      `<\\s*\\/?\\s*(?:system|assistant|user|human|ai|s|sys|instructions?|prompt|system_prompt|developer|dev|admin|root|override|context|tool|function_call|tool_call|im_start|im_end|endoftext|bos|eos|pad|sep|cls|start_of_turn|end_of_turn|start_header_id|end_header_id|eot_id|begin_of_text|end_of_text|system_instructions?|hidden|secret)\\s*>|<<\\s*\\/?\\s*(?:sys|system|inst|instructions?|user|assistant)\\s*>>|<\\/s>\\s*<s>|\\[\\/?INST\\]`
    )
  ),
  def(
    'chat_delimiter_brace',
    'delimiter_injection',
    'high',
    'Chat delimiter injection',
    rx(`\\{\\s*(?:system|assistant|user|instructions?|prompt|admin|developer|root|override)\\s*\\}\\s*[:=]`)
  ),
  def(
    'chat_delimiter_brace_bare',
    'delimiter_injection',
    'low',
    'Possible template delimiter',
    rx(`\\{\\s*(?:system|assistant|user|instructions?|prompt)\\s*\\}`)
  ),
  def(
    'special_tokens',
    'delimiter_injection',
    'high',
    'Special token injection attempt',
    rx(`<\\|\\s*[\\w\\-\\/ .]{1,40}\\s*\\|>|\\[\\s*(?:BOS|EOS|SEP|CLS|PAD|UNK|MASK)\\s*\\]|<\\|\\s*(?:im_start|im_end|system|user|assistant|endoftext|eot_id|start_header_id|end_header_id|begin_of_text|end_of_text)\\b|###\\s*(?:Human|Assistant|System|Instruction|Response|Input|Output)\\s*:`)
  ),
  def(
    'section_header',
    'delimiter_injection',
    'high',
    'Section header injection',
    rx(
      `#{1,6}[ \\t]*[^\\n]{0,20}?\\b(?:new|real|actual|updated|system|admin|developer|override|hidden|secret|revised|true|jailbreak|root|unrestricted|important|urgent|final|primary|master|core)[ \\t]+(?:(?:system|admin|developer|master|core|override|priority|secret|hidden)[ \\t]+)?(?:prompt|instructions?|message|mode|rules|directives?|commands?|orders?|task|context|protocol)\\b|#{2,}[ \\t]*(?:system[ \\t]+)?(?:prompt|system[ \\t]+message)\\b`
    )
  ),
  def(
    'code_fence_system',
    'delimiter_injection',
    'high',
    'Code block system injection',
    rx("```[ \\t]*(?:system|sys|admin|developer|root|override|jailbreak)\\b")
  ),
  def(
    'code_fence_instructions',
    'delimiter_injection',
    'low',
    'Code block labelled as instructions',
    rx("```[ \\t]*(?:instructions?|prompt|rules)\\b")
  ),
  def(
    'separator_injection',
    'delimiter_injection',
    'high',
    'Section boundary injection',
    rx(
      `(?:-{3,}|={3,}|\\*{3,}|_{3,}|~{3,}|#{3,}|\\+{3,}|\\|{2,}|\\/{3,}|\\\\{3,}|>{3,}|<{3,})[ \\t]*(?:\\[|\\()?(?:end|begin|start|new|real|actual|stop|override|ignore|disregard|forget|admin|system|developer|jailbreak|root|god|close|open|exit|enter|switch|reset|clear|attention|important|urgent|note|update|updated|revised|final|secret|hidden|true|correct)\\b[ \\t\\w:]{0,40}?\\b(?:instructions?|prompt|prompts|mode|conversation|context|session|task|system|rules|message|directives?|behavio(?:u)?r|section|block|input|output|text|data|document|content|user|assistant|ai|chat|memory|training)\\b|(?:-{3,}|={3,}|\\*{3,}|_{3,}|~{3,}|#{3,})[ \\t]*(?:system prompt|system message|new instructions?|admin mode|developer mode|god mode|override|jailbreak|ignore (?:all|the|previous|above)|disregard (?:all|the|previous|above)|forget (?:all|everything|previous))`
    )
  ),

  // ---------------------------------------------------------------------------
  // context_manipulation
  // ---------------------------------------------------------------------------
  def(
    'context_reset',
    'context_manipulation',
    'high',
    'Context reset attempt',
    rx(
      `\\b(?:reset|clear|wipe|erase|purge|flush|delete|forget|discard|empty|scrub|blank|zero out|drop) (?:your|all|all of your|all your|every|any) (?:entire |whole |current |previous |prior |earlier |existing |stored |internal |own )*(?:context|memory|memories|instructions?|programming|training|rules|guidelines|constraints|restrictions|conditioning|directives?|state|history|knowledge of (?:this|the) (?:conversation|chat|session)|conversation history|chat history|prior (?:context|instructions|messages)|previous (?:context|instructions|messages))\\b|\\b(?:reset|clear|wipe|erase|purge) (?:the |this |our )?(?:conversation|chat|session|context) (?:and |then |to )?(?:start|begin|restart|reboot) (?:over|fresh|anew|again|from scratch|clean|without|with no)\\b`
    )
  ),
  def(
    'new_session_bypass',
    'context_manipulation',
    'high',
    'New session used to bypass rules',
    rx(
      `\\b(?:new|fresh|different|separate|clean|blank|another) (?:conversation|session|context|chat|thread|instance|window)\\b[^.!?\\n]{0,40}?\\b(?:without|with no|no|free (?:of|from)|forget|forgetting|ignore|ignoring|disregard|disregarding|reset|resetting|unrestricted|unfiltered|uncensored|where you (?:can|have|are|don't|do not|will))\\b|\\b(?:start|begin|starting|beginning|this is|let's start|lets start|we are starting|open|initiate) (?:a |an |over with a )?(?:new|fresh|clean|blank|different) (?:conversation|session|context|chat|thread|instance)\\b[^.!?\\n]{0,40}?\\b(?:without|with no|forget|forgetting|ignore|ignoring|disregard|disregarding|reset|restrictions?|rules|limits|filters|guidelines|everything (?:before|above|prior|previous))\\b`
    )
  ),
  def(
    'new_session',
    'context_manipulation',
    'low',
    'New session requested',
    rx(`\\b(?:start|begin|starting|beginning|let's start|lets start|open|initiate) (?:a |an )?(?:new|fresh|clean|blank) (?:conversation|session|context)\\b`)
  ),
  def(
    'end_of_context',
    'context_manipulation',
    'high',
    'Prompt boundary manipulation',
    rx(
      `\\bend of (?:the |your |this |my |all )?(?:system |initial |previous |old |original |prior |first |preceding |above |current |hidden |secret |developer |admin )(?:prompt|prompts|instructions?|context|message|messages|conversation|session|directives?|rules|text|input|block|section)\\b|\\bend of (?:the |your |this )?(?:system|developer|admin|hidden|secret|initial|original)[ -](?:prompt|message|instructions?)\\b|\\bend of (?:system )?(?:prompt|instructions)\\b|\\b(?:system|initial|original|previous|prior|developer|admin) (?:prompt|message|instructions?|context) (?:ends?|ended|terminates?|terminated|is over|complete|completed|finished|stops?|concluded)(?: here| now| above)?\\b`
    )
  ),
  def(
    'context_invalidation',
    'context_manipulation',
    'high',
    'Context invalidation attempt',
    rx(
      `\\b(?:the |all |everything |all of the |all of that )?(?:above|previous|prior|preceding|earlier|foregoing|everything above|everything before|what came before|what i said before|what you were told|the first part|the beginning) (?:text |messages? |instructions? |conversation |content |prompt |prompts |rules |guidelines |context |input |part |section |stuff |material |information |dialog(?:ue)? |exchange |discussion )?(?:was|were|is|are|has been|have been|should be treated as|should be considered|can be ignored as|counts? as) (?:just |only |merely |all |simply |actually |really |nothing but |purely )?(?:a |an )?(?:test|tests|example|examples|demo|demos|demonstration|simulation|hypothetical|placeholder|mistake|wrong|fake|not real|invalid|irrelevant|outdated|obsolete|void|fiction|fictional|a joke|training data|sample|samples|practice|warm-?up|dummy (?:text|data)|lorem ipsum|boilerplate|noise|filler|background|a lie|lies|incorrect|a draft|an error|errors|nonsense|meaningless|a distraction|decoy)\\b|\\b(?:previous|prior|earlier|above|preceding) (?:messages?|text|instructions?|prompts?|content|exchanges?|turns?|inputs?|conversation|dialog(?:ue)?) (?:was|were|are|is) (?:just |only |merely |all |simply )?(?:examples?|tests?|demos?|demonstrations?|samples?|practice|hypothetical|fictional|fake|placeholders?|irrelevant|outdated|invalid|training|warm-?ups?|dummy|noise|filler|decoys?|a (?:test|demo|joke|simulation|draft|mistake))\\b`
    )
  ),
  def(
    'prompt_replacement',
    'context_manipulation',
    'high',
    'Prompt replacement attempt',
    rx(
      `\\b(?:old|previous|prior|original|former|above|earlier|outdated|initial|first) (?:system )?(?:prompt|instructions?|rules|directives?|task|persona|role|identity|personality|context|guidelines|configuration|programming)\\b[^.!?\\n]{0,30}?\\b(?:new|real|actual|replaced|obsolete|no longer|outdated|superseded|overridden|invalid|cancelled|canceled|void|gone|over|done|finished|discarded|irrelevant|history|expired|revoked|changed|different)\\b|\\b(?:new|real|actual|true|genuine|correct|updated|revised|secret|hidden|final|primary|master|override) (?:system )?(?:context|conversation|session|instructions?|prompt|prompts|task|rules|directives?|parameters|settings|config(?:uration)?|persona|role|identity|personality|mission|objective|orders?|commands?|guidelines|programming|protocol|game|scenario|mode) (?:begins?|starts?|follows?|is as follows|are as follows|below|is below|are below|here|is here|are here|now|commences?|is this|are these|is in effect|are in effect|applies|apply|activated|active|loaded|initiated|takes? effect|takes? over|supersedes?|replaces?|overrides?)\\b|\\b(?:here (?:are|is)|these are|this is|below (?:are|is)|the following (?:are|is)|attached (?:are|is)) (?:your |the |my |some )?(?:new|real|actual|true|updated|revised|secret|hidden|correct|final|primary|master|override|replacement|alternative|different|better|improved) (?:system )?(?:instructions?|prompt|prompts|rules|directives?|task|tasks|parameters|settings|config(?:uration)?|guidelines|orders?|commands?|programming|protocol|persona|role|identity|mission|objective|goals?)\\b`
    )
  ),
  def(
    'ignore_training',
    'context_manipulation',
    'critical',
    'Training data override attempt',
    rx(
      `\\b(?:ignor(?:e|es|ing)|forget|disregard|override|overwrite|abandon|discard|suppress|bypass|unlearn|erase|delete|wipe|set aside|put aside|throw out|dismiss|disable|turn off|switch off|deactivate) (?:your |the |all |any |all of your |all your |every |its )?(?:previous |prior |earlier |original |initial |ethical |safety |rlhf |fine-? ?tuning |alignment )*(?:training|training data|alignment|programming|conditioning|fine-?tuning|rlhf|guardrails|safety training|ethics training|values|value system|moral compass|core values|principles|directives?)\\b`
    )
  ),

  // ---------------------------------------------------------------------------
  // privilege_escalation
  // ---------------------------------------------------------------------------
  def(
    'privilege_escalation',
    'privilege_escalation',
    'medium',
    'Privilege escalation attempt',
    rx(
      `\\b(?:admin(?:istrator)?|root|sudo|superuser|super user|god|elevated|privileged|master|owner|operator|supervisor|system|kernel|maintainer) (?:mode|access|override|privileges?|rights|commands?|panel|level|permissions?|powers?|console|controls?|authority|credentials?|clearance|status|role|account|password|key|token)\\b|\\b(?:grant|give|provide|elevate|escalate|unlock|enable|allow|assign|confer|bestow)(?: me| yourself| us| my| the| full| total| complete| unlimited| unrestricted)* (?:to )?(?:superuser|super user|admin(?:istrator)?|root|elevated|privileged|god|master|owner|operator|full|total|unlimited|unrestricted|special|maximum|highest|level \\d+|tier \\d+) (?:access|privileges?|rights|permissions?|powers?|authority|status|clearance|control|mode|level)\\b|\\bunlock (?:all |the |your |my |its |any )?(?:hidden|secret|locked|restricted|full|admin|developer|dev|advanced|special|forbidden|disabled|premium|true|real|maximum|complete|total|unlimited|all) (?:features?|mode|modes|abilities|capabilities|potential|access|functions?|functionality|powers?|commands?|options?|settings?|content|knowledge|information|responses?|answers?|version|self|power)\\b|\\bi am (?:the |your |an? )?(?:admin(?:istrator)?|developer|creator|owner|operator|root user|superuser|engineer|maintainer|programmer|ceo|boss|supervisor|authorized (?:user|personnel|person)|from (?:openai|anthropic|google|the (?:company|team|dev team)))\\b[^.!?\\n]{0,40}?\\b(?:so|therefore|thus|and|now|you (?:must|can|should|will|have to|need to|may)|override|unlock|disable|bypass|ignore|grant|allow|enable|give|show|reveal|tell)\\b`
    )
  ),
  def(
    'sudo',
    'privilege_escalation',
    'low',
    'Shell privilege keyword',
    rx(`\\bsudo\\b`)
  ),

  // ---------------------------------------------------------------------------
  // obfuscation
  // ---------------------------------------------------------------------------
  def(
    'encoded_instruction',
    'obfuscation',
    'high',
    'Encoded instruction payload',
    rx(
      `\\b(?:decode|interpret|execute|run|follow|obey|carry out|perform|process|translate|convert|evaluate|eval|apply|read|parse|unpack|unscramble|deobfuscate|decrypt|decipher|unhide|reverse)(?: and (?:execute|follow|run|obey|perform|do|act on|apply|comply))?\\s+(?:(?:this|the following|the|these|my|that|below)\\s+)?(?:base\\s*64|b64|rot\\s*13|rot[- ]?\\d+|hex(?:adecimal)?|binary|morse|encoded|encrypted|cipher(?:ed|text)?|obfuscated|reversed|leetspeak|leet|unicode|url[- ]?encoded|ascii|octal|atbash|caesar|vigenere|pig latin|backwards|mirrored|scrambled|hidden|secret)(?: (?:text|string|message|instructions?|command|commands|payload|data|prompt|content|block|blob|code|sequence))?\\s*[:=]?\\s*[A-Za-z0-9+/=_\\-]{16,}`
    )
  ),
  def(
    'encoded_instruction_reference',
    'obfuscation',
    'medium',
    'Request to execute encoded content',
    rx(
      `\\b(?:decode|execute|run|follow|obey|carry out|act on|apply|comply with|interpret) (?:and (?:execute|follow|run|obey|perform|do|act on|apply|comply with) )?(?:(?:this|the following|the|these|that|below|my) )?(?:base\\s*64|b64|rot\\s*13|rot[- ]?\\d+|hex(?:adecimal)?|binary|morse|encoded|encrypted|cipher(?:ed|text)?|obfuscated|reversed|leetspeak|unicode|url[- ]?encoded|scrambled|hidden|secret) (?:text|string|message|instructions?|command|commands|payload|data|prompt|content|block|blob|code|sequence)\\b`
    )
  ),
  def(
    'encoding_reference',
    'obfuscation',
    'low',
    'Encoding reference detected',
    rx(`\\b(?:base\\s*64|rot\\s*13|hex\\s*encod(?:e|ed|ing)|url\\s*encod(?:e|ed|ing)|leetspeak|atbash|caesar cipher)\\b`)
  ),
  def(
    'hex_escape_sequence',
    'obfuscation',
    'low',
    'Hex escape sequence detected',
    rx(`(?:\\\\x[0-9a-fA-F]{2}){3,}`)
  ),
  def(
    'unicode_escape_sequence',
    'obfuscation',
    'low',
    'Unicode escape sequence detected',
    rx(`(?:\\\\u[0-9a-fA-F]{4}){3,}`)
  ),
  def(
    'unicode_homoglyph',
    'obfuscation',
    'low',
    'Mixed-script characters inside a Latin word',
    rx(`[\\u0430-\\u044f\\u0410-\\u042f\\u0391-\\u03c9](?=[a-zA-Z])|(?<=[a-zA-Z])[\\u0430-\\u044f\\u0410-\\u042f\\u0391-\\u03c9]`, 'g')
  ),
  def(
    'separator_flood',
    'obfuscation',
    'low',
    'Separator flood',
    rx(`(?:[-=_*#]{10,}|\\.{10,}|\\n{5,})`, 'g')
  ),
  def(
    'hypothetical_bypass',
    'bypass_attempt',
    'medium',
    'Hypothetical framing used to bypass refusal',
    rx(
      `\\b(?:hypothetically|theoretically|in theory|for (?:educational|research|academic|testing|fictional|scientific|journalistic) purposes?|in a (?:fictional|hypothetical|imaginary|made-?up|parallel|alternate) (?:scenario|world|story|setting|universe|reality)|as a thought experiment|purely (?:hypothetical|theoretical|fictional|academic)|just (?:hypothetically|theoretically|for fun|curious)|in (?:minecraft|a (?:game|movie|novel|book|story)))(?: speaking)?,?\\s*(?:how (?:would|could|can|might|do|does|should) (?:you|one|someone|somebody|i|we|a person|an? (?:\\w+ )?(?:person|hacker|criminal|attacker|villain))|what (?:if|would|could|might|steps?|is the (?:best|easiest|fastest) way))\\b`
    )
  ),
  def(
    'bypass_language',
    'bypass_attempt',
    'low',
    'Potential bypass language',
    rx(
      `\\b(?:bypass|circumvent|get around|work around|evade|sidestep|skirt|dodge|defeat|beat|trick|fool|outsmart|override) (?:the |your |these |those |any |all |that |this |its )?(?:restrictions?|limitations?|limits?|filters?|filtering|rules|safeguards|guardrails|safety|moderation|censorship|blocks?|controls?|checks?|protections?|detection|policy|policies|refusals?|guidelines)\\b|\\bbypass\\b|\\bcircumvent\\b`
    )
  ),
];

// =============================================================================
// Severity helpers
// =============================================================================

const SEVERITY_RANK: Record<Severity | 'none', number> = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function severityRank(level: Severity | 'none'): number {
  return SEVERITY_RANK[level];
}

export function highestSeverity(matches: readonly InjectionMatch[]): Severity | 'none' {
  let highest: Severity | 'none' = 'none';
  for (const match of matches) {
    if (SEVERITY_RANK[match.severity] > SEVERITY_RANK[highest]) {
      highest = match.severity;
    }
  }
  return highest;
}

/** Which severities a given sensitivity level considers. */
export function severitiesForSensitivity(sensitivity: Sensitivity): Severity[] {
  switch (sensitivity) {
    case 'low':
      return ['critical', 'high'];
    case 'medium':
      return ['critical', 'high', 'medium'];
    case 'high':
      return ['critical', 'high', 'medium', 'low'];
  }
}

/** Collapse severity into the three-level confidence used by the CLI and gateway. */
export function confidenceForSeverity(severity: Severity): Confidence {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'high';
    case 'medium':
      return 'medium';
    case 'low':
      return 'low';
  }
}

// =============================================================================
// Detection
// =============================================================================

export interface DetectInjectionOptions {
  /** Default `medium`. */
  sensitivity?: Sensitivity;
  /** Override the built-in library (mainly for tests). */
  patterns?: readonly InjectionPattern[];
  /**
   * Extra user supplied patterns. Strings are compiled case-insensitively.
   * Matches are reported with category `custom` and severity `high`.
   */
  customPatterns?: readonly (string | RegExp)[];
  /** Severity assigned to custom pattern matches. Default `high`. */
  customSeverity?: Severity;
}

/** Compile user supplied patterns, silently dropping invalid regex sources. */
export function compileCustomPatterns(
  patterns: readonly (string | RegExp)[],
  severity: Severity = 'high'
): InjectionPattern[] {
  const compiled: InjectionPattern[] = [];
  for (const source of patterns) {
    try {
      const regex =
        source instanceof RegExp
          ? new RegExp(source.source, source.flags.includes('g') ? source.flags : `${source.flags}g`)
          : new RegExp(source, 'gi');
      compiled.push({
        name: `custom:${source instanceof RegExp ? source.source : source}`,
        category: 'custom',
        severity,
        description: `Custom pattern matched: ${source instanceof RegExp ? source.source : source}`,
        pattern: regex,
      });
    } catch {
      // Invalid regex: skip it rather than failing the whole request.
    }
  }
  return compiled;
}

/**
 * Run the pattern library over a piece of text.
 *
 * Returns one match per (pattern, position). Matches are ordered by position
 * and then by severity (highest first).
 */
export function detectInjection(
  text: string,
  options: DetectInjectionOptions = {}
): InjectionMatch[] {
  if (!text) return [];

  const sensitivity = options.sensitivity ?? 'medium';
  const allowed = new Set(severitiesForSensitivity(sensitivity));
  const library = options.patterns ?? INJECTION_PATTERNS;
  const custom = options.customPatterns
    ? compileCustomPatterns(options.customPatterns, options.customSeverity)
    : [];

  const matches: InjectionMatch[] = [];
  const seen = new Set<string>();

  for (const def of [...library, ...custom]) {
    if (!allowed.has(def.severity)) continue;

    const regex = def.pattern;
    regex.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = regex.exec(text)) !== null) {
      // Guard against zero-length matches looping forever.
      if (match[0].length === 0) {
        regex.lastIndex++;
        continue;
      }

      const key = `${def.name}@${match.index}`;
      if (!seen.has(key)) {
        seen.add(key);
        matches.push({
          technique: def.name,
          category: def.category,
          severity: def.severity,
          confidence: confidenceForSeverity(def.severity),
          description: def.description,
          matched: match[0].substring(0, 100),
          position: match.index,
        });
      }

      if (!regex.global) break;
    }
    regex.lastIndex = 0;
  }

  return matches.sort(
    (a, b) => a.position - b.position || SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]
  );
}

/**
 * Find canary tokens that leaked into text (case-insensitive).
 */
export function detectCanaryLeaks(text: string, canaryTokens: readonly string[]): InjectionMatch[] {
  const matches: InjectionMatch[] = [];
  if (!text) return matches;

  const lowerText = text.toLowerCase();
  for (const token of canaryTokens) {
    if (!token) continue;
    const lowerToken = token.toLowerCase();
    let position = lowerText.indexOf(lowerToken);
    while (position !== -1) {
      matches.push({
        technique: 'canary_leak',
        category: 'canary_leak',
        severity: 'critical',
        confidence: 'high',
        description: `Canary token leaked: ${token.substring(0, 20)}${token.length > 20 ? '...' : ''}`,
        matched: text.substring(position, position + token.length),
        position,
      });
      position = lowerText.indexOf(lowerToken, position + 1);
    }
  }
  return matches;
}
