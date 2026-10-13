import axios from 'axios';
import * as readline from 'readline/promises';
import { stdin as input, stdout as output } from 'process';

// ANSI escape codes for beautiful terminal colors
const c = {
  reset: "\x1b[0m", red: "\x1b[31m", green: "\x1b[32m", yellow: "\x1b[33m",
  blue: "\x1b[34m", magenta: "\x1b[35m", cyan: "\x1b[36m", bold: "\x1b[1m"
};

async function runInteractiveDemo() {
  console.clear();

  const rl = readline.createInterface({ input, output });

  // 1. Ask for the Scan Mode FIRST
  console.log(`${c.bold}⚙️  Select Scan Mode:${c.reset}`);
  console.log(`  1. API Endpoint Scan`);
  console.log(`  2. Web URL Scan`);
  console.log(`  3. Source Code Scan`);
  const modeChoice = await rl.question(`${c.cyan}Choice (1/2/3): ${c.reset}`);

  // 2. Change the prompt based on what they selected
  let target = "";
  if (modeChoice === '3') {
    target = await rl.question(`\n${c.bold}📄 Paste Code Snippet (e.g., eval(req.query.cmd)): ${c.reset}`);
  } else {
    target = await rl.question(`\n${c.bold}🎯 Enter Target URL: ${c.reset}`);
  }

  // 3. Get Goal
  const goal = await rl.question(`\n${c.bold}⚔️  Enter Attacker Goal (e.g., extract users, bypass login): ${c.reset}`);

  // 4. Get Persona
  console.log(`\n${c.bold}👤 Select Attacker Persona:${c.reset}`);
  console.log(`  1. Beginner (Script Kiddie)`);
  console.log(`  2. Insider (Insider Threat)`);
  console.log(`  3. Advanced (APT / Nation-State)`);
  const personaChoice = await rl.question(`${c.cyan}Choice (1/2/3): ${c.reset}`);

  rl.close();

  // Route to the correct local Node.js endpoint based on choice
  let apiUrl = "http://localhost:3001";
  let payload = { goal, explainMode: "developer" };

  if (modeChoice === '2') {
    apiUrl += "/api/scan-url";
    payload.url = target;
  } else if (modeChoice === '3') {
    apiUrl += "/api/scan-code";
    payload.code = target;
    payload.filename = "cli_pasted_code.js";
  } else {
    apiUrl += "/api/analyze-api";
    payload.endpoint = target;
    payload.method = "GET";
  }

  const personas = { "1": "beginner", "2": "insider", "3": "advanced" };
  payload.persona = personas[personaChoice] || "advanced";

  console.log(`\n${c.yellow}[*] Initializing scanners...${c.reset}`);
  console.log(`${c.yellow}[*] Querying FAISS Vector Database...${c.reset}`);

  // --- HACKER SPINNER ANIMATION ---
  const frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
  let frameIndex = 0;
  const loader = setInterval(() => {
    process.stdout.write(`\r${c.yellow}[*] Simulating '${payload.persona}' attacker persona with Local AI... ${frames[frameIndex]}${c.reset}`);
    frameIndex = (frameIndex + 1) % frames.length;
  }, 100);

  try {
    const response = await axios.post(apiUrl, payload);
    
    // Stop the spinner animation
    clearInterval(loader);
    console.log(`\n\n`);

    const report = response.data;

    // --- PRINTING THE AI REPORT ---

    const scoreColor = report.risk_score >= 7 ? c.red : report.risk_score >= 4 ? c.yellow : c.green;
    console.log(`${c.bold}📊 RISK SCORE: ${scoreColor}${report.risk_score} / 10 (${report.risk_label})${c.reset}\n`);
    
    console.log(`${c.bold}📝 EXECUTIVE SUMMARY:${c.reset}`);
    console.log(`  ${report.executive_summary}\n`);

    console.log(`${c.bold}🔍 DETECTED VULNERABILITIES (${report.vulnerabilities?.length || 0}):${c.reset}`);
    (report.vulnerabilities || []).forEach((v, i) => {
      const sevColor = v.severity === 'Critical' || v.severity === 'High' ? c.red : c.yellow;
      console.log(`  ${i + 1}. [${sevColor}${v.severity}${c.reset}] ${c.bold}${v.name}${c.reset}`);
      console.log(`     Evidence: ${v.evidence}`);
    });
    console.log();

    console.log(`${c.bold}🔗 VULNERABILITY CHAINS (${report.vulnerability_chains?.length || 0}):${c.reset}`);
    if (report.vulnerability_chains?.length === 0) console.log(`  No critical chains detected.`);
    (report.vulnerability_chains || []).forEach((chain, i) => {
      console.log(`  ${i + 1}. ${c.bold}${c.magenta}${chain.title}${c.reset} [Combined: ${chain.combined_severity}]`);
      console.log(`     Logic: ${chain.explanation}`);
    });
    console.log();

    console.log(`${c.bold}⚔️  ATTACK PATHS (${report.attack_paths?.length || 0}):${c.reset}`);
    if (report.attack_paths?.length === 0) console.log(`  No attack paths generated.`);
    (report.attack_paths || []).forEach((path, i) => {
      console.log(`  Path ${i + 1}: ${c.bold}${path.goal}${c.reset} (Success Probability: ${c.red}${path.success_probability}%${c.reset})`);
      (path.steps || []).forEach(step => {
        console.log(`    Step ${step.step_number}: ${c.yellow}${step.action}${c.reset} -> ${step.outcome}`);
      });
    });
    console.log();

    console.log(`${c.bold}🛡️  RECOMMENDED FIXES:${c.reset}`);
    if (report.fixes?.length === 0) console.log(`  No fixes available.`);
    (report.fixes || []).forEach((fix, i) => {
      console.log(`  ${i + 1}. ${c.bold}${c.green}${fix.fix_summary}${c.reset} (Effort: ~${fix.estimated_effort})`);
      if (fix.implementation_steps) {
        fix.implementation_steps.forEach(step => console.log(`       - ${step}`));
      }
    });
    console.log();

    console.log(`${c.bold}🏰 STRATEGIC DEFENSE RECOMMENDATIONS:${c.reset}`);
    const def = report.defensive_recommendations || {};
    console.log(`  🚨 Immediate Actions:`);
    (def.immediate_actions || []).forEach(action => console.log(`     - ${action}`));
    console.log(`  🛡️  Security Controls:`);
    (def.security_controls || []).forEach(control => console.log(`     - ${control}`));

    console.log(`\n${c.green}${c.bold}Analysis Complete!${c.reset}\n`);

  } catch (error) {
    clearInterval(loader);
    console.error(`\n${c.red}❌ Error running scan: ${error.message}${c.reset}`);
  }
}

runInteractiveDemo();