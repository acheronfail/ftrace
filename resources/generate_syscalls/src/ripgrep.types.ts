//
// TypeScript definitions for ripgrep's JSON output.
// See https://docs.rs/grep-printer/*/grep_printer/struct.JSON.html
//

export interface RgText {
  /**
   * Only present if the match data is UTF-8
   */
  text: string;
}

export interface RgBytes {
  /**
   * Base64 encoding of underlying bytes (when not valid utf-8)
   */
  bytes: string;
}

export type RgData = RgText | RgBytes;

export interface RgBegin {
  type: 'begin';
  data: {
    path: RgData;
  };
}

export interface RgMatch {
  type: 'match';
  data: {
    path: RgData;
    lines: RgData;
    line_number: number;
    absolute_offset: number;
    submatches: RgSubmatch[];
  };
}

export interface RgSubmatch {
  match: RgData;
  start: number;
  end: number;
}

export interface RgContext {
  type: 'context';
  data: {
    path: RgData;
    lines: RgData;
    line_number: number;
    absolute_offset: number;
    submatches: [];
  };
}

export interface RgEnd {
  type: 'end';
  data: {
    path: RgData;
    /**
     * null when no binary data was found, or if binary mode was disabled
     */
    binary_offset: number | null;
    stats: RgStats;
  };
}

export interface RgDuration {
  secs: number;
  nanos: number;
  human: string;
}

export interface RgSummary {
  type: 'summary';
  data: {
    elapsed_total: RgDuration;
    stats: RgStats;
  };
}

export interface RgStats {
  elapsed: RgDuration;
  searches: number;
  searches_with_match: number;
  bytes_searched: number;
  bytes_printed: number;
  matches_lines: number;
  matches: number;
}

export type RgMessage = RgBegin | RgMatch | RgContext | RgEnd | RgSummary;
