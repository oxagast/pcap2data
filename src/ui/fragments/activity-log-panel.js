const activityLogPanelMarkup = `
  <div id="activity-log-header">
    <span>Activity Log</span>
    <button id="close-log-btn" aria-label="Close log">×</button>
  </div>
  <div id="activity-log-path"></div>
  <div id="activity-log-entries"></div>
  <div id="activity-log-search-bar">
    <input id="activity-log-search" type="text" placeholder="Search log entries..." />
  </div>
`;

module.exports = { activityLogPanelMarkup };
