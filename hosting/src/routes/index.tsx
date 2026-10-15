import { createFileRoute } from '@tanstack/react-router';
import { useEffect, useRef } from 'react';
export const Route = createFileRoute('/')({
  head: () => ({ links: [{ rel: 'canonical', href: 'https://patchpilot-workbench.higgsfield.app' }] }),
  component: Workbench,
});
function Workbench() {
  const frame = useRef<HTMLIFrameElement>(null);
  useEffect(() => {
    const iframe = frame.current;
    if (!iframe) return;
    let observer: ResizeObserver | undefined;
    const attach = () => {
      observer?.disconnect();
      const doc = iframe.contentDocument;
      if (!doc?.body) return;
      const fit = () => { iframe.style.height = Math.ceil(doc.body.getBoundingClientRect().height + 4) + 'px'; };
      observer = new ResizeObserver(fit);
      observer.observe(doc.body);
      fit();
    };
    iframe.addEventListener('load', attach);
    attach();
    return () => { iframe.removeEventListener('load', attach); observer?.disconnect(); };
  }, []);
  return <>
    <a className="skip" href="#workbench">Skip to the workbench</a>
    <header className="host-header"><a className="wordmark" href="/">Patch<span>Pilot</span><small>WORKBENCH</small></a><nav aria-label="Main navigation"><a href="#workbench">Code workbench</a><a href="/lab/audit.html">Open full screen ↗</a></nav></header>
    <main>
      <section className="host-hero"><div><p className="eyebrow">MAKE THE NEXT CHANGE COUNT</p><h1>Find the bug.<br/><span>Understand the fix.</span></h1><p className="hero-copy">Bring your code. See the problem, understand the change, and build something better.</p><div className="pills"><span>Errors & reliability</span><span>Security checks</span><span>Efficiency proposals</span></div><p className="privacy">● Local checks stay in your browser. AI review sends your snippet to Nebius only when you choose it.</p></div><img src="/lab/banner.svg" alt="Orange and purple code inspection instrument" width="640" height="400"/></section>
      <section id="workbench" aria-label="Interactive code workbench"><div className="workspace-head"><p>YOUR SPACE TO DEBUG</p><a href="/lab/audit.html">Open full screen ↗</a></div><iframe ref={frame} title="PatchPilot code workbench" src="/lab/audit.html?embed=1" sandbox="allow-scripts allow-same-origin allow-downloads" allow="clipboard-write" /></section>
      <noscript><p className="noscript">Enable JavaScript to run local checks and request a Nebius AI review.</p></noscript>
    </main>
    <footer className="host-footer"><span>PatchPilot · Review, test, then ship.</span><span>NVIDIA Nemotron on Nebius Token Factory · optional AI review</span></footer>
  </>;
}
