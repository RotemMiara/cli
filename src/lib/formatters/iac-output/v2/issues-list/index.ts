import { EOL } from 'os';
import * as capitalize from 'lodash.capitalize';
import * as isEmpty from 'lodash.isempty';
import * as debug from 'debug';

import { IacOutputMeta } from '../../../../types';
import { colors, contentPadding } from '../utils';
import { formatScanResultsNewOutput } from './formatters';
import { formatIssue } from './issue';
import { SEVERITY } from '../../../../snyk-test/common';
import { FormattedOutputResult } from './types';
import { FormattedResult } from '../../../../../cli/commands/test/iac/local-execution/types';

export function getIacDisplayedIssues(
  results: FormattedResult[],
  outputMeta: IacOutputMeta,
): string {
  const titleOutput = colors.title('Issues');

  const formattedResults = formatScanResultsNewOutput(results, outputMeta);

  if (isEmpty(formattedResults.results)) {
    return (
      titleOutput +
      EOL +
      contentPadding +
      colors.success.bold('No vulnerable paths were found!')
    );
  }

  const severitySectionsOutput = Object.values(SEVERITY)
    .filter((severity) => !!formattedResults.results[severity])
    .map((severity) => {
      const severityResults: FormattedOutputResult[] =
        formattedResults.results[severity];

      const titleOutput = colors.title(
        `${capitalize(severity)} Severity Issues: ${severityResults.length}`,
      );

      const issuesOutput = severityResults
        .sort(
          (severityResult1, severityResult2) =>
            severityResult1.targetFile.localeCompare(
              severityResult2.targetFile,
            ) ||
            severityResult1.issue.id.localeCompare(severityResult2.issue.id),
        )
        .map(formatIssue)
        .join(EOL.repeat(2));

      debug(
        `iac display output - ${severity} severity ${severityResults.length} issues`,
      );

      return titleOutput + EOL.repeat(2) + issuesOutput;
    })
    .join(EOL.repeat(2));

  return titleOutput + EOL.repeat(2) + severitySectionsOutput;
}
