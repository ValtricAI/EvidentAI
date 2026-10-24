import type { Analyzer, AnalyzerType } from '../types.js';
import { heuristicAnalyzer } from './heuristic.js';
import { llmJudgeAnalyzer } from './llm-judge.js';

export { HeuristicAnalyzer, heuristicAnalyzer } from './heuristic.js';
export { LLMJudgeAnalyzer, llmJudgeAnalyzer } from './llm-judge.js';

const analyzerRegistry: Record<AnalyzerType, Analyzer> = {
  heuristic: heuristicAnalyzer,
  'llm-judge': llmJudgeAnalyzer,
};

export function getAnalyzer(type: AnalyzerType): Analyzer {
  const analyzer = analyzerRegistry[type];
  if (!analyzer) {
    throw new Error(`Unknown analyzer type: ${type}`);
  }
  return analyzer;
}

export function getAnalyzers(types: AnalyzerType[]): Analyzer[] {
  return types.map(getAnalyzer);
}
