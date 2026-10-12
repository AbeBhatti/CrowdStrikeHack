import { useEffect, useMemo, useState } from "react";
import { KillChainGraph } from "./KillChainGraph";
import { forbiddenInText } from "./textRules";

const API = "http://127.0.0.1:8000";

type Call = {
  id: string;
  text: string;
  mode: string;
  audio_token?: string | null;
  status: string;
};

type LibraryRule = {
  name: string;
  stage_detected: string;
  origin_company: string;
  validation?: { companies?: string[]; fp_per_day?: number };
};

export function App() {
  const [scenario, setScenario] = useState("russellmitchell");
  const [metrics, setMetrics] = useState<Record<string, unknown>>({});
  const [forecast, setForecast] = useState<Record<string, unknown>>({});
  const [library, setLibrary] = useState<LibraryRule[]>([]);
  const [recs, setRecs] = useState<Array<Record<string, unknown>>>([]);
  const [calls, setCalls] = useState<Call[]>([]);
  const [voiceMode, setVoiceMode] = useState("demo");
  const [activeStage, setActiveStage] = useState("webshell");
  const [whatIf, setWhatIf] = useState<string | null>(null);
  const [guard, setGuard] = useState<Array<Record<string, unknown>>>([]);
  const [events, setEvents] = useState<Array<Record<string, unknown>>>([]);

  const refresh = async () => {
    const [m, f, lib, r, v] = await Promise.all([
      fetch(`${API}/metrics`).then((x) => x.json()),
      fetch(`${API}/forecast/demo`).then((x) => x.json()),
      fetch(`${API}/library`).then((x) => x.json()),
      fetch(`${API}/recommendations`).then((x) => x.json()),
      fetch(`${API}/oncall/voice_mode`).then((x) => x.json()),
    ]);
    setMetrics(m);
    setForecast(f);
    setLibrary(lib);
    setRecs(r);
    setVoiceMode(v.mode);
  };

  useEffect(() => {
    refresh().catch(console.error);
    const t = setInterval(() => {
      fetch(`${API}/events`)
        .then((x) => x.json())
        .then(setEvents)
        .catch(() => undefined);
    }, 2000);
    return () => clearInterval(t);
  }, []);

  const stages = useMemo(
    () => ["recon", "web_scan", "webshell", "reverse_shell", "privilege_escalation", "exfil"],
    []
  );

  const prevented = useMemo(() => {
    if (!whatIf) return [];
    const idx = stages.indexOf(whatIf);
    return idx >= 0 ? stages.slice(idx + 1) : [];
  }, [whatIf, stages]);

  const startReplay = async () => {
    await fetch(`${API}/replay/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario, speed: 5000 }),
    });
    setActiveStage("web_scan");
    setTimeout(() => setActiveStage("webshell"), 800);
    setTimeout(() => setActiveStage("reverse_shell"), 1600);
    await refresh();
  };

  const simulateCall = async () => {
    const call = await fetch(`${API}/oncall/simulate_call`, { method: "POST" }).then((x) =>
      x.json()
    );
    setCalls((c) => [...c, call]);
  };

  const keypad = async (digit: number, callId: string) => {
    const res = await fetch(`${API}/oncall/keypad?digit=${digit}&call_id=${callId}`, {
      method: "POST",
    }).then((x) => x.json());
    setCalls((cs) =>
      cs.map((c) => (c.id === callId ? { ...c, status: res.status || c.status } : c))
    );
  };

  const toggleVoice = async () => {
    const next = voiceMode === "demo" ? "normal" : "demo";
    const res = await fetch(`${API}/oncall/voice_mode`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode: next }),
    }).then((x) => x.json());
    setVoiceMode(res.mode);
  };

  const injection = async () => {
    const res = await fetch(`${API}/guard/injection_demo`, { method: "POST" }).then((x) =>
      x.json()
    );
    setGuard((g) => [...g, res]);
  };

  const uiStrings = [
    "On-Call Security Teammate",
    "Kill chain",
    "What-if assumes blocking a stage stops later stages",
    "Phone simulator",
  ];
  const bad = uiStrings.find(forbiddenInText);
  if (bad) {
    console.error("forbidden text", bad);
  }

  return (
    <div className="layout">
      <div>
        <div className="panel">
          <h1>On-Call Security Teammate</h1>
          <p className="muted">
            Local triage, forecast, decoys, and phone approvals. Dashboard is the audit trail.
          </p>
          <div className="row">
            <select value={scenario} onChange={(e) => setScenario(e.target.value)}>
              <option value="russellmitchell">russellmitchell</option>
              <option value="santos">santos</option>
            </select>
            <button onClick={startReplay}>Start replay</button>
            <button onClick={simulateCall}>Simulate call</button>
            <button onClick={injection}>Show injection block</button>
            <button onClick={toggleVoice}>Voice: {voiceMode}</button>
          </div>
        </div>

        <div className="panel" style={{ marginTop: "0.75rem" }}>
          <h2>Kill chain</h2>
          <p className="muted">What-if assumes blocking a stage stops later stages.</p>
          <KillChainGraph
            stages={stages}
            active={activeStage}
            prevented={prevented}
            onSelect={(s) => setWhatIf(s)}
          />
          <div className="row" style={{ marginTop: "0.5rem" }}>
            {stages.map((s) => (
              <button key={s} onClick={() => setWhatIf(s)}>
                Block at {s}
              </button>
            ))}
            <button onClick={() => setWhatIf(null)}>Clear what-if</button>
          </div>
          {whatIf && (
            <p className="mono">
              Defense at {whatIf}. Prevented downstream: {prevented.join(", ") || "none"}. Reach:{" "}
              {stages.indexOf(whatIf) + 1}/{stages.length}
            </p>
          )}
        </div>

        <div className="panel" style={{ marginTop: "0.75rem" }}>
          <h2>Event log</h2>
          <table>
            <thead>
              <tr>
                <th>type</th>
                <th>detail</th>
              </tr>
            </thead>
            <tbody>
              {events.slice(-12).map((e, i) => (
                <tr key={i}>
                  <td className="mono">{String(e.type)}</td>
                  <td className="mono">{JSON.stringify(e).slice(0, 140)}</td>
                </tr>
              ))}
              {guard.map((g, i) => (
                <tr key={`g${i}`}>
                  <td className="signal">injection_blocked</td>
                  <td className="mono">{JSON.stringify(g.reasons)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="side">
        <div className="panel">
          <h2>Live counters</h2>
          <p className="mono">metrics: {JSON.stringify(metrics)}</p>
          <h3>Forecast</h3>
          <p className="mono">
            next={String(forecast.next_stage)} p={String(forecast.probability)} window=
            {JSON.stringify(forecast.window_minutes)}
          </p>
        </div>

        <div className="panel">
          <h2>Defense library</h2>
          <table>
            <thead>
              <tr>
                <th>rule</th>
                <th>stage</th>
                <th>origin</th>
              </tr>
            </thead>
            <tbody>
              {library.map((r) => (
                <tr key={r.name + r.origin_company}>
                  <td className="mono">{r.name}</td>
                  <td>{r.stage_detected}</td>
                  <td className="mono">{r.origin_company}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="panel">
          <h2>On-call</h2>
          <p className="muted">Phone simulator (used when Twilio keys are absent).</p>
          {calls.map((c) => (
            <div className="phone-sim" key={c.id}>
              <div className="signal">Incoming call ({c.mode})</div>
              <p>{c.text}</p>
              {c.audio_token && (
                <audio controls src={`${API}/oncall/audio/${c.audio_token}`} />
              )}
              <div className="row">
                <button onClick={() => keypad(1, c.id)}>1</button>
                <button onClick={() => keypad(2, c.id)}>2</button>
                <button onClick={() => keypad(3, c.id)}>3</button>
              </div>
              <p className="mono">status={c.status}</p>
            </div>
          ))}
        </div>

        <div className="panel">
          <h2>Recommendations</h2>
          <table>
            <thead>
              <tr>
                <th>type</th>
                <th>target</th>
                <th>lost</th>
              </tr>
            </thead>
            <tbody>
              {recs.slice(0, 8).map((r, i) => (
                <tr key={i}>
                  <td>{String(r.type)}</td>
                  <td className="mono">
                    {String(r.target_rule)}@{String(r.host_role)}
                  </td>
                  <td>{String(r.attack_stage_alerts_lost)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
