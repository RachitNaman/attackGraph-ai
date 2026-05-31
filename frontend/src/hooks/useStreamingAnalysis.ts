export function useStreamingAnalysis() {
  return {
    start: () => undefined,
    events: [],
    isStreaming: false,
  };
}
