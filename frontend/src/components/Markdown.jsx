import { Fragment } from "react";

/**
 * Tiny, dependency-free renderer for the subset of Markdown LLM replies
 * normally use: fenced code, inline code, bold, bullet/number lists and
 * paragraphs. Output is built from React elements (never innerHTML), so
 * model output cannot inject markup.
 */

function renderInline(text, keyPrefix) {
  const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g);

  return parts.map((part, index) => {
    const key = `${keyPrefix}-${index}`;

    if (part.startsWith("`") && part.endsWith("`") && part.length > 2) {
      return <code key={key}>{part.slice(1, -1)}</code>;
    }

    if (part.startsWith("**") && part.endsWith("**") && part.length > 4) {
      return <strong key={key}>{part.slice(2, -2)}</strong>;
    }

    return <Fragment key={key}>{part}</Fragment>;
  });
}

function Markdown({ text }) {
  const source = String(text ?? "");
  const blocks = [];
  const fence = /```(\w*)\n?([\s\S]*?)```/g;

  let last = 0;
  let match;

  while ((match = fence.exec(source)) !== null) {
    if (match.index > last) {
      blocks.push({ type: "text", value: source.slice(last, match.index) });
    }

    blocks.push({ type: "code", lang: match[1], value: match[2] });
    last = match.index + match[0].length;
  }

  if (last < source.length) {
    blocks.push({ type: "text", value: source.slice(last) });
  }

  return (
    <div className="markdown">
      {blocks.map((block, blockIndex) => {
        if (block.type === "code") {
          return (
            <pre key={blockIndex} className="code-block">
              {block.lang && <span className="code-lang">{block.lang}</span>}
              <code>{block.value.replace(/\n$/, "")}</code>
            </pre>
          );
        }

        return block.value
          .split(/\n{2,}/)
          .filter((chunk) => chunk.trim())
          .map((chunk, chunkIndex) => {
            const key = `${blockIndex}-${chunkIndex}`;
            const lines = chunk.split("\n");

            if (lines.every((line) => /^\s*[-*•]\s+/.test(line))) {
              return (
                <ul key={key}>
                  {lines.map((line, i) => (
                    <li key={i}>
                      {renderInline(line.replace(/^\s*[-*•]\s+/, ""), `${key}-${i}`)}
                    </li>
                  ))}
                </ul>
              );
            }

            if (lines.every((line) => /^\s*\d+[.)]\s+/.test(line))) {
              return (
                <ol key={key}>
                  {lines.map((line, i) => (
                    <li key={i}>
                      {renderInline(line.replace(/^\s*\d+[.)]\s+/, ""), `${key}-${i}`)}
                    </li>
                  ))}
                </ol>
              );
            }

            const heading = chunk.match(/^#{1,4}\s+(.*)$/);

            if (heading && lines.length === 1) {
              return <h4 key={key}>{renderInline(heading[1], key)}</h4>;
            }

            return (
              <p key={key}>
                {lines.map((line, i) => (
                  <Fragment key={i}>
                    {i > 0 && <br />}
                    {renderInline(line, `${key}-${i}`)}
                  </Fragment>
                ))}
              </p>
            );
          });
      })}
    </div>
  );
}

export default Markdown;
