/** Search-param keys used by the Alerts screen (kept out of the component file for fast refresh). */
export const ALERT_PARAM_KEYS = ['q', 'band', 'severity', 'source', 'storyline', 'rcj', 'oap', 'sort', 'order', 'offset', 'limit'] as const
export type AlertParamKey = (typeof ALERT_PARAM_KEYS)[number]
