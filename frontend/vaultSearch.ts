// Finding entries: every word of the query has to appear in the entry's row
// or in its table's name. Text and links are searched; password and MFA
// cells never are.

import type { PassTableData } from "./PassTable";

/** Lower case without accents, so "Cafe" finds "café". */
function fold(text: string): string {
  return text.normalize("NFKD").replace(/\p{M}/gu, "").toLocaleLowerCase();
}

/** The words to look for; none means "show everything". */
export function searchTerms(query: string): string[] {
  return fold(query).split(/\s+/).filter(Boolean);
}

/** Which rows of `table` match, by row index. */
export function matchingRows(table: PassTableData, terms: string[]): boolean[] {
  const name = fold(table.name);
  return table.rowIds.map((_, row) => {
    const text = [name];
    for (const column of table.columns) {
      if (column.type === "textarea") text.push(column.data[row] ?? "");
      else if (column.type === "link") {
        const link = column.data[row];
        if (link != null) text.push(link.url, link.text ?? "");
      }
    }
    const haystack = fold(text.join("\n"));
    return terms.every((term) => haystack.includes(term));
  });
}
