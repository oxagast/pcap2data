// Controls the Stats workspace UI and capture analytics rendering.

const threadName = "Stats";
const h337 = require("heatmap.js");

const DEFAULT_HEATMAP_INTENSITY = 100;
const DEFAULT_HEATMAP_TIGHTNESS = 145;
const DEFAULT_HEATMAP_POINT_SIZE = 90;
const DEFAULT_HEATMAP_BLUR = 72;
const DEFAULT_HEATMAP_MAP_ZOOM = 100;
const MIN_HEATMAP_MAP_ZOOM = 100;
const MAX_HEATMAP_MAP_ZOOM = 2000;
const HEATMAP_MAP_ZOOM_SLIDER_STEP = 1;
const HEATMAP_SELECTION_ZOOM_LARGE_AREA_PERCENT = 200;
const HEATMAP_SELECTION_ZOOM_MID_AREA_PERCENT = 450;
const HEATMAP_SELECTION_ZOOM_TINY_AREA_PERCENT = 800;
const HEATMAP_SELECTION_AREA_TINY_RATIO = 0.001;
const HEATMAP_SELECTION_AREA_MID_RATIO = 0.02;
const HEATMAP_SELECTION_AREA_LARGE_RATIO = 0.4;
const HEATMAP_LOCATION_CLICK_ZOOM_PERCENT = 550;
const HEATMAP_LOCATION_CLICK_CITY_ZOOM_PERCENT = 1600;
const HEATMAP_LOCATION_SELECTION_ASPECT_WIDTH = 16;
const HEATMAP_LOCATION_SELECTION_ASPECT_HEIGHT = 9;
const HEATMAP_LOCATION_SELECTION_SIZE_SCALE = 0.5;
const HEATMAP_SELECTION_MIN_PIXELS = 12;
const HEATMAP_SELECTION_DRAW_MS = 320;
const HEATMAP_SELECTION_BLINK_MS = 360;
const HEATMAP_ZOOM_SETTLE_MS = 420;
const HEATMAP_SELECTION_RUSH_MS = 420;
const HEATMAP_ZOOM_TRANSITION_RASTER_PERCENT = 125;
const HEATMAP_GRID_BASE_CELL_SIZE_X = 28;
const HEATMAP_GRID_BASE_CELL_SIZE_Y = 22;
const HEATMAP_GRID_MIN_CELL_SIZE = 6;
const HEATMAP_GRID_ZOOM_RESPONSE_EXPONENT = 2;
const HEATMAP_SCOPE_CAPTURE = "capture";
const HEATMAP_SCOPE_FILTERED = "filtered";
const HEATMAP_METRIC_PACKETS = "packets";
const HEATMAP_METRIC_BYTES = "bytes";
const WIKIMEDIA_WORLD_MAP_ASSET_PATH = "../assets/images/world.svg";
const WIKIMEDIA_WORLD_MAP_WIDTH = 1404.7773;
const WIKIMEDIA_WORLD_MAP_HEIGHT = 600.81262;
const WIKIMEDIA_WORLD_MAP_ASPECT_RATIO =
  WIKIMEDIA_WORLD_MAP_WIDTH / WIKIMEDIA_WORLD_MAP_HEIGHT;
const WIKIMEDIA_WORLD_MAP_PROJECTION_BOUNDS = Object.freeze({
  left: 0.007,
  right: 0.993,
  top: 0.02,
  bottom: 0.98,
});
const WIKIMEDIA_WORLD_MAP_PROJECTION_ZOOM_X = 0.29;
const WIKIMEDIA_WORLD_MAP_PROJECTION_ZOOM_Y = 0.83;
const WIKIMEDIA_WORLD_MAP_PROJECTION_OFFSET_X = -1.30;
const WIKIMEDIA_WORLD_MAP_PROJECTION_OFFSET_Y = 0.39;
let lastStatsMapProjectionCalibration = null;
let statsBasemapSvgSourceCache = null;
const statsBasemapSvgMarkupThemeCache = new Map();
const statsBasemapSvgDataUriThemeCache = new Map();
const statsBasemapRasterThemeCache = new Map();
const BASEMAP_RASTER_MIN_ZOOM_PERCENT = 125;
const BASEMAP_RASTER_ZOOM_BUCKET_PERCENT = 20;
const BASEMAP_RASTER_HIGH_ZOOM_BUCKET_PERCENT = 10;
const BASEMAP_RASTER_HIGH_ZOOM_THRESHOLD_PERCENT = 400;
const BASEMAP_RASTER_MAX_DIMENSION = 16384;
const BASEMAP_RASTER_MAX_PIXELS = 68_000_000;
const BASEMAP_RASTER_CACHE_LIMIT = 8;

// Sets inline svg style property.
function setInlineSvgStyleProperty(styleText, propertyName, propertyValue) {
  const declarations = String(styleText || "")
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean)
    .filter((part) => !part.toLowerCase().startsWith(`${propertyName.toLowerCase()}:`));
  declarations.unshift(`${propertyName}:${propertyValue}`);
  return declarations.join(";");
}

// Sets inline svg fill on matching element markup.
function setInlineSvgFillOnElementMarkup(elementMarkup, fillColor) {
  if (!elementMarkup || !fillColor) return elementMarkup;

  const styleAttrRegex = /\sstyle="([^"]*)"/i;
  if (styleAttrRegex.test(elementMarkup)) {
    return elementMarkup.replace(styleAttrRegex, (_match, styleValue) => {
      const nextStyle = setInlineSvgStyleProperty(styleValue, "fill", fillColor);
      return ` style="${nextStyle}"`;
    });
  }

  const fillAttrRegex = /\sfill="[^"]*"/i;
  if (fillAttrRegex.test(elementMarkup)) {
    return elementMarkup.replace(fillAttrRegex, ` fill="${fillColor}"`);
  }

  return elementMarkup.replace(/\/>$|>$/, (ending) => ` fill="${fillColor}"${ending}`);
}

// Applies themed land fill color to svg content.
function applyStatsBasemapLandFill(svgSource, landFillColor) {
  if (!svgSource || !landFillColor) return svgSource;

  const groupStyleRegex = /(<g[^>]*id="layer1"[^>]*style=")([^"]*)(")/i;
  if (groupStyleRegex.test(svgSource)) {
    return svgSource.replace(groupStyleRegex, (_fullMatch, prefix, styleValue, suffix) => {
      const nextStyle = setInlineSvgStyleProperty(styleValue, "fill", landFillColor);
      return `${prefix}${nextStyle}${suffix}`;
    });
  }

  const groupTagRegex = /<g[^>]*id="layer1"[^>]*>/i;
  if (groupTagRegex.test(svgSource)) {
    return svgSource.replace(groupTagRegex, (groupTag) =>
      setInlineSvgFillOnElementMarkup(groupTag, landFillColor),
    );
  }

  // Fallback used by world.svg and other country-path maps.
  return svgSource.replace(/<path\b[^>]*\/?>/gi, (pathTag) =>
    setInlineSvgFillOnElementMarkup(pathTag, landFillColor),
  );
}

// Applies themed water gradient fill to svg background.
function applyStatsBasemapWaterFill(svgSource, waterTopColor, waterBottomColor) {
  if (!svgSource || !waterTopColor || !waterBottomColor) return svgSource;

  const defsBlock = [
    '<defs id="ps-heatmap-water-defs">',
    '  <linearGradient id="ps-heatmap-water-gradient" x1="0" y1="0" x2="0" y2="1">',
    `    <stop offset="0%" stop-color="${waterTopColor}"/>`,
    `    <stop offset="100%" stop-color="${waterBottomColor}"/>`,
    "  </linearGradient>",
    "</defs>",
    '<rect id="ps-heatmap-water-bg" x="0" y="0" width="100%" height="100%" fill="url(#ps-heatmap-water-gradient)"/>',
  ].join("\n");

  return svgSource.replace(/<svg\b[^>]*>/i, (svgTag) => `${svgTag}\n${defsBlock}`);
}

// Handles fetch stats basemap svg source.
async function fetchStatsBasemapSvgSource() {
  if (typeof statsBasemapSvgSourceCache === "string" && statsBasemapSvgSourceCache.length > 0) {
    return statsBasemapSvgSourceCache;
  }
  const response = await fetch(WIKIMEDIA_WORLD_MAP_ASSET_PATH);
  if (!response.ok) {
    throw new Error(`Unable to load heatmap basemap SVG: ${response.status}`);
  }
  const svgText = await response.text();
  statsBasemapSvgSourceCache = svgText;
  return svgText;
}

// Builds themed stats basemap svg.
function buildThemedStatsBasemapSvg(
  svgSource,
  landFillColor,
  waterTopColor,
  waterBottomColor,
) {
  if (!svgSource) return svgSource;

  const withWaterFill = applyStatsBasemapWaterFill(
    svgSource,
    waterTopColor,
    waterBottomColor,
  );
  return applyStatsBasemapLandFill(withWaterFill, landFillColor);
}

// Returns themed stats basemap color values from active theme.
function getStatsBasemapThemeColors(rootStyles) {
  const resolveColor = (primaryVar, fallbackVar, hardFallback) =>
    String(rootStyles.getPropertyValue(primaryVar) || rootStyles.getPropertyValue(fallbackVar) || hardFallback)
      .trim();

  return {
    landFillColor: resolveColor(
      "--stats-heatmap-land-fill-color",
      "--color-1",
      "#cccccc",
    ),
    waterTopColor: resolveColor(
      "--stats-heatmap-water-color-3-top",
      "--stats-heatmap-water-color-1",
      "#0f1720",
    ),
    waterBottomColor: resolveColor(
      "--stats-heatmap-water-color-3-bottom",
      "--stats-heatmap-water-color-2",
      "#04070b",
    ),
  };
}

// Builds cache key for themed basemap.
function buildStatsBasemapThemeCacheKey(themeColors) {
  return `${String(themeColors.landFillColor || "").trim()}|${String(themeColors.waterTopColor || "").trim()}|${String(themeColors.waterBottomColor || "").trim()}`;
}

// Returns themed stats basemap svg markup.
async function getThemedStatsBasemapSvgMarkup(themeColors) {
  const themeKey = buildStatsBasemapThemeCacheKey(themeColors);
  if (statsBasemapSvgMarkupThemeCache.has(themeKey)) {
    return {
      themeKey,
      svgMarkup: statsBasemapSvgMarkupThemeCache.get(themeKey),
    };
  }

  const svgSource = await fetchStatsBasemapSvgSource();
  const themedSvg = buildThemedStatsBasemapSvg(
    svgSource,
    themeColors.landFillColor,
    themeColors.waterTopColor,
    themeColors.waterBottomColor,
  );
  statsBasemapSvgMarkupThemeCache.set(themeKey, themedSvg);
  return { themeKey, svgMarkup: themedSvg };
}

// Returns themed stats basemap data uri.
async function getThemedStatsBasemapDataUri(themeColors) {
  const { themeKey, svgMarkup } = await getThemedStatsBasemapSvgMarkup(themeColors);
  if (statsBasemapSvgDataUriThemeCache.has(themeKey)) {
    return {
      themeKey,
      dataUri: statsBasemapSvgDataUriThemeCache.get(themeKey),
    };
  }

  const dataUri = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svgMarkup)}`;
  statsBasemapSvgDataUriThemeCache.set(themeKey, dataUri);
  return { themeKey, dataUri };
}

// Loads image from url.
function loadImageFromUrl(url) {
  return new Promise((resolve, reject) => {
    const imageEl = new Image();
    imageEl.onload = () => resolve(imageEl);
    imageEl.onerror = reject;
    imageEl.src = url;
  });
}

// Returns zoom bucket percent for raster keying.
function getBasemapRasterZoomBucketPercent(zoomPercent) {
  const bucketStep = zoomPercent >= BASEMAP_RASTER_HIGH_ZOOM_THRESHOLD_PERCENT
    ? BASEMAP_RASTER_HIGH_ZOOM_BUCKET_PERCENT
    : BASEMAP_RASTER_ZOOM_BUCKET_PERCENT;
  return Math.round(zoomPercent / bucketStep) * bucketStep;
}

// Bounds raster dimensions to avoid oversized canvas allocations.
function clampBasemapRasterDimensions(width, height) {
  let boundedWidth = Math.max(1, Math.round(width));
  let boundedHeight = Math.max(1, Math.round(height));

  const limitByDimension = Math.min(
    BASEMAP_RASTER_MAX_DIMENSION / boundedWidth,
    BASEMAP_RASTER_MAX_DIMENSION / boundedHeight,
    1,
  );
  if (limitByDimension < 1) {
    boundedWidth = Math.max(1, Math.round(boundedWidth * limitByDimension));
    boundedHeight = Math.max(1, Math.round(boundedHeight * limitByDimension));
  }

  const pixelCount = boundedWidth * boundedHeight;
  if (pixelCount > BASEMAP_RASTER_MAX_PIXELS) {
    const areaScale = Math.sqrt(BASEMAP_RASTER_MAX_PIXELS / pixelCount);
    boundedWidth = Math.max(1, Math.round(boundedWidth * areaScale));
    boundedHeight = Math.max(1, Math.round(boundedHeight * areaScale));
  }

  return {
    width: boundedWidth,
    height: boundedHeight,
  };
}

// Stores raster in cache and evicts oldest entries.
function setStatsBasemapRasterCacheEntry(cacheKey, dataUri) {
  if (statsBasemapRasterThemeCache.has(cacheKey)) {
    statsBasemapRasterThemeCache.delete(cacheKey);
  }
  statsBasemapRasterThemeCache.set(cacheKey, dataUri);
  while (statsBasemapRasterThemeCache.size > BASEMAP_RASTER_CACHE_LIMIT) {
    const oldestKey = statsBasemapRasterThemeCache.keys().next().value;
    if (!oldestKey) break;
    statsBasemapRasterThemeCache.delete(oldestKey);
  }
}

// Rasterizes svg data uri to png data uri.
async function rasterizeSvgDataUriToPngDataUri(svgDataUri, width, height) {
  const targetWidth = Math.max(1, Math.floor(width));
  const targetHeight = Math.max(1, Math.floor(height));
  const sourceImage = await loadImageFromUrl(svgDataUri);
  const canvasEl = document.createElement("canvas");
  canvasEl.width = targetWidth;
  canvasEl.height = targetHeight;
  const context = canvasEl.getContext("2d");
  if (!context) {
    throw new Error("Unable to rasterize basemap SVG: 2D canvas unavailable");
  }
  context.imageSmoothingEnabled = true;
  context.imageSmoothingQuality = "high";
  context.clearRect(0, 0, targetWidth, targetHeight);
  context.drawImage(sourceImage, 0, 0, targetWidth, targetHeight);
  return canvasEl.toDataURL("image/png");
}

// Applies themed stats basemap image.
async function applyThemedStatsBasemapImage(basemapImageEl, options = {}) {
  if (!basemapImageEl || !window.getComputedStyle) return;
  const rootStyles = window.getComputedStyle(document.documentElement);
  const themeColors = getStatsBasemapThemeColors(rootStyles);
  const { zoomPercent, boundsWidth, boundsHeight } = options || {};
  const normalizedZoomPercent = clampHeatmapMapZoomPercent(
    zoomPercent,
    DEFAULT_HEATMAP_MAP_ZOOM,
  );
  const themeKey = buildStatsBasemapThemeCacheKey(themeColors);
  const requestId =
    Number.parseInt(basemapImageEl.dataset.rasterRequestId || "0", 10) + 1;
  basemapImageEl.dataset.rasterRequestId = String(requestId);

  try {
    const { dataUri: themedSvgDataUri } = await getThemedStatsBasemapDataUri(
      themeColors,
    );

    const supportsZoomRaster =
      Number.isFinite(boundsWidth)
      && Number.isFinite(boundsHeight)
      && boundsWidth > 0
      && boundsHeight > 0
      && normalizedZoomPercent >= BASEMAP_RASTER_MIN_ZOOM_PERCENT;

    if (!supportsZoomRaster) {
      const sourceKey = `${themeKey}|vector`;
      if (basemapImageEl.dataset.basemapSourceKey !== sourceKey) {
        basemapImageEl.src = themedSvgDataUri;
        basemapImageEl.dataset.basemapSourceKey = sourceKey;
      }
      return;
    }

    const zoomBucketPercent = getBasemapRasterZoomBucketPercent(normalizedZoomPercent);
    const deviceScale = Math.min(
      4,
      Math.max(1, Number(window.devicePixelRatio) || 1),
    );
    const highZoomBoost = zoomBucketPercent >= 600 ? 1.12 : 1;
    const targetScale = (zoomBucketPercent / 100) * deviceScale * highZoomBoost;
    const rasterDims = clampBasemapRasterDimensions(
      boundsWidth * targetScale,
      boundsHeight * targetScale,
    );
    const rasterWidth = rasterDims.width;
    const rasterHeight = rasterDims.height;
    const rasterKey = `${themeKey}|${rasterWidth}x${rasterHeight}`;

    if (statsBasemapRasterThemeCache.has(rasterKey)) {
      if (basemapImageEl.dataset.rasterRequestId !== String(requestId)) return;
      if (basemapImageEl.dataset.basemapSourceKey !== rasterKey) {
        basemapImageEl.src = statsBasemapRasterThemeCache.get(rasterKey);
        basemapImageEl.dataset.basemapSourceKey = rasterKey;
      }
      return;
    }

    const rasterDataUri = await rasterizeSvgDataUriToPngDataUri(
      themedSvgDataUri,
      rasterWidth,
      rasterHeight,
    );
    setStatsBasemapRasterCacheEntry(rasterKey, rasterDataUri);
    if (basemapImageEl.dataset.rasterRequestId !== String(requestId)) return;
    if (basemapImageEl.dataset.basemapSourceKey !== rasterKey) {
      basemapImageEl.src = rasterDataUri;
      basemapImageEl.dataset.basemapSourceKey = rasterKey;
    }
    return;
  } catch {
    // Fall through to legacy path below.
  }

  try {
    const { themeKey: fallbackThemeKey, dataUri: legacyDataUri } =
      await getThemedStatsBasemapDataUri(themeColors);
    const sourceKey = `${fallbackThemeKey}|vector`;
    if (basemapImageEl.dataset.basemapSourceKey !== sourceKey) {
      basemapImageEl.src = legacyDataUri;
      basemapImageEl.dataset.basemapSourceKey = sourceKey;
    }
    return;
  } catch {
    // Final fallback below.
  }

  basemapImageEl.src = WIKIMEDIA_WORLD_MAP_ASSET_PATH;
  basemapImageEl.dataset.basemapSourceKey = "asset-default";
}

// Handles clamp projection setting.
function clampProjectionSetting(value, fallback, minimum, maximum) {
  const numericValue = Number(value);
  if (!Number.isFinite(numericValue)) return fallback;
  return Math.min(maximum, Math.max(minimum, numericValue));
}

// Returns whether protocol like field name.
function isProtocolLikeFieldName(fieldName, fieldValue) {
  if (fieldName.includes(".")) return false;
  if (!fieldValue || typeof fieldValue !== "object") return false;
  if (Array.isArray(fieldValue)) return false;
  // Exclude transport metadata objects such as "TCP Flag Data".
  if (!/^[A-Za-z][A-Za-z0-9]*$/.test(fieldName)) return false;
  return true;
}


// Returns credentials from keystore.
function getCredentialsFromKeystore() {

  return window.keystoreCredsCount;
}

// Returns top talkers.
function getTopTalkers(capturedPackets, topN = 5) {
  const talkerCounts = new Map();

  for (const host of Object.keys(capturedPackets["host"] || {})) {
    const packets = capturedPackets["host"][host];
    if (!Array.isArray(packets)) continue;

    for (const pkt of packets) {
      const pi = pkt?.["packet.info"];
      if (!pi) continue;

      const srcIp = pi?.["IP"]?.["ip.src.addr"] ?? pi?.["IP"]?.["Source IP"];
      const dstIp = pi?.["IP"]?.["ip.dst.addr"] ?? pi?.["IP"]?.["Destination IP"];
      if (srcIp) {
        talkerCounts.set(srcIp, (talkerCounts.get(srcIp) || 0) + 1);
      }
      if (dstIp) {
        talkerCounts.set(dstIp, (talkerCounts.get(dstIp) || 0) + 1);
      }
    }
  }

  return Array.from(talkerCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, topN)
    .map(([ip, count]) => ({ ip, count }));
}

// Returns unique credential list.
function getUniqueCredentialList() {
  const uniquePasswords = window.keystoreCreds || new Set();
  // mask the passwords for privacy by using only first and last 2 chars and
  // the rest should be stars
  const maskedPasswords = [...uniquePasswords].map((password) => {
    if (password.length <= 4) {
      const firstChar = password.charAt(0) || "";
      const lastChar = password.charAt(password.length - 1) || "";
      const middleStars = "*".repeat(Math.max(0, password.length - 2));
      return `${firstChar}${middleStars}${lastChar}`;
    };
    const firstTwo = password.slice(0, 2);
    const lastTwo = password.slice(-2);
    const middleStars = "*".repeat(password.length - 4);
    return `${firstTwo}${middleStars}${lastTwo}`;
  });
  return maskedPasswords.sort();
};

// Parses stats geo coordinate.
function parseStatsGeoCoordinate(value, min, max) {
  const parsedValue = Number(value);
  if (!Number.isFinite(parsedValue)) return null;
  if (parsedValue < min || parsedValue > max) return null;
  return parsedValue;
}

// Returns geo location label.
function getGeoLocationLabel(locationData, fallbackLabel) {
  const city = normalizeStatsTextValue(locationData?.["City"]);
  const country = normalizeStatsTextValue(locationData?.["Country"]);
  if (city && country) return `${city}, ${country}`;
  return country || city || fallbackLabel || "Unknown";
}

// Collects internet location point.
function collectInternetLocationPoint(locationData, fallbackLabel, ipAddress) {
  if (!locationData || typeof locationData !== "object") return null;

  const statusLabel = normalizeStatsTextValue(locationData?.["Location"]);
  if (statusLabel && /^(localnet|error:)/i.test(statusLabel)) {
    return null;
  }

  const latitude = parseStatsGeoCoordinate(locationData?.["Latitude"], -90, 90);
  const longitude = parseStatsGeoCoordinate(locationData?.["Longitude"], -180, 180);
  if (latitude === null || longitude === null) return null;

  return {
    latitude,
    longitude,
    label: getGeoLocationLabel(locationData, fallbackLabel),
    city: normalizeStatsTextValue(locationData?.["City"]),
    country: normalizeStatsTextValue(locationData?.["Country"]),
    ipAddress: normalizeStatsTextValue(ipAddress),
  };
}

// Builds location traffic query from point.
function buildLocationTrafficQueryFromPoint(locationPoint) {
  const city = normalizeStatsTextValue(locationPoint?.city);
  const country = normalizeStatsTextValue(locationPoint?.country);
  if (city || country) {
    const clauses = [];
    if (city) {
      clauses.push(`loc.src.city: ${city} || loc.dst.city: ${city}`);
    }
    if (country) {
      clauses.push(`loc.src.country: ${country} || loc.dst.country: ${country}`);
    }
    return clauses.join(" || ");
  }

  const ipAddresses = Array.isArray(locationPoint?.ipAddresses)
    ? locationPoint.ipAddresses
    : locationPoint?.ipAddress
      ? [locationPoint.ipAddress]
      : [];
  const uniqueIps = [...new Set(
    ipAddresses
      .map((ipAddress) => normalizeStatsTextValue(ipAddress))
      .filter((ipAddress) => ipAddress !== null),
  )];
  if (uniqueIps.length === 0) return null;

  return uniqueIps
    .map((ipAddress) => `(ip.src.addr: ${ipAddress} || ip.dst.addr: ${ipAddress})`)
    .join(" || ");
}

// Handles project geo point.
function projectGeoPoint(
  latitude,
  longitude,
  width,
  height,
  projectionBounds = WIKIMEDIA_WORLD_MAP_PROJECTION_BOUNDS,
  projectionCalibration = null,
) {
  const calibration = projectionCalibration || {
    zoomX: WIKIMEDIA_WORLD_MAP_PROJECTION_ZOOM_X,
    zoomY: WIKIMEDIA_WORLD_MAP_PROJECTION_ZOOM_Y,
    offsetX: WIKIMEDIA_WORLD_MAP_PROJECTION_OFFSET_X,
    offsetY: WIKIMEDIA_WORLD_MAP_PROJECTION_OFFSET_Y,
  };
  const baseCenterX = (projectionBounds.left + projectionBounds.right) / 2;
  const baseCenterY = (projectionBounds.top + projectionBounds.bottom) / 2;
  const calibratedCenterX = baseCenterX + calibration.offsetX;
  const calibratedCenterY = baseCenterY + calibration.offsetY;

  const baseWidth = projectionBounds.right - projectionBounds.left;
  const baseHeight = projectionBounds.bottom - projectionBounds.top;
  const calibratedWidth = baseWidth / calibration.zoomX;
  const calibratedHeight = baseHeight / calibration.zoomY;

  const calibratedLeft = Math.max(0, calibratedCenterX - (calibratedWidth / 2));
  const calibratedRight = Math.min(1, calibratedCenterX + (calibratedWidth / 2));
  const calibratedTop = Math.max(0, calibratedCenterY - (calibratedHeight / 2));
  const calibratedBottom = Math.min(1, calibratedCenterY + (calibratedHeight / 2));

  const usableWidth = width * (calibratedRight - calibratedLeft);
  const usableHeight = height * (calibratedBottom - calibratedTop);
  const projectedX =
    (width * calibratedLeft) + (((longitude + 180) / 360) * usableWidth);
  const projectedY =
    (height * calibratedTop) + (((90 - latitude) / 180) * usableHeight);
  return {
    x: Math.min(width - 1, Math.max(0, Math.round(projectedX))),
    y: Math.min(height - 1, Math.max(0, Math.round(projectedY))),
  };
}

// Returns calibrated projection bounds.
function getCalibratedProjectionBounds(
  projectionBounds = WIKIMEDIA_WORLD_MAP_PROJECTION_BOUNDS,
  projectionCalibration = null,
) {
  const calibration = projectionCalibration || {
    zoomX: WIKIMEDIA_WORLD_MAP_PROJECTION_ZOOM_X,
    zoomY: WIKIMEDIA_WORLD_MAP_PROJECTION_ZOOM_Y,
    offsetX: WIKIMEDIA_WORLD_MAP_PROJECTION_OFFSET_X,
    offsetY: WIKIMEDIA_WORLD_MAP_PROJECTION_OFFSET_Y,
  };
  const baseCenterX = (projectionBounds.left + projectionBounds.right) / 2;
  const baseCenterY = (projectionBounds.top + projectionBounds.bottom) / 2;
  const calibratedCenterX = baseCenterX + calibration.offsetX;
  const calibratedCenterY = baseCenterY + calibration.offsetY;
  const baseWidth = projectionBounds.right - projectionBounds.left;
  const baseHeight = projectionBounds.bottom - projectionBounds.top;
  const calibratedWidth = baseWidth / calibration.zoomX;
  const calibratedHeight = baseHeight / calibration.zoomY;

  return {
    left: Math.max(0, calibratedCenterX - (calibratedWidth / 2)),
    right: Math.min(1, calibratedCenterX + (calibratedWidth / 2)),
    top: Math.max(0, calibratedCenterY - (calibratedHeight / 2)),
    bottom: Math.min(1, calibratedCenterY + (calibratedHeight / 2)),
  };
}

// Converts viewport point into geo coordinates for current zoom/pan state.
function convertViewportPointToGeoCoordinates(
  bounds,
  point,
  viewState = {},
  projectionCalibration = null,
  projectionBounds = WIKIMEDIA_WORLD_MAP_PROJECTION_BOUNDS,
) {
  if (!bounds || !point) return null;
  const transform = getHeatmapViewTransform(bounds, viewState);
  const scale = Math.max(0.0001, transform.scale);

  const mapX = Math.min(
    bounds.width,
    Math.max(0, (Number(point.x) - bounds.left - transform.translateX) / scale),
  );
  const mapY = Math.min(
    bounds.height,
    Math.max(0, (Number(point.y) - bounds.top - transform.translateY) / scale),
  );

  const calibrated = getCalibratedProjectionBounds(projectionBounds, projectionCalibration);
  const usableWidth = Math.max(1, bounds.width * (calibrated.right - calibrated.left));
  const usableHeight = Math.max(1, bounds.height * (calibrated.bottom - calibrated.top));

  const normalizedX = ((mapX - (bounds.width * calibrated.left)) / usableWidth);
  const normalizedY = ((mapY - (bounds.height * calibrated.top)) / usableHeight);

  return {
    latitude: Math.min(90, Math.max(-90, 90 - (normalizedY * 180))),
    longitude: Math.min(180, Math.max(-180, (normalizedX * 360) - 180)),
  };
}

// Converts geo coordinates into viewport point for current zoom/pan state.
function convertGeoCoordinatesToViewportPoint(
  bounds,
  latitude,
  longitude,
  viewState = {},
  projectionCalibration = null,
) {
  if (!bounds) return null;
  const projected = projectGeoPoint(
    latitude,
    longitude,
    bounds.width,
    bounds.height,
    WIKIMEDIA_WORLD_MAP_PROJECTION_BOUNDS,
    projectionCalibration,
  );
  const transform = getHeatmapViewTransform(bounds, viewState);
  return {
    x: bounds.left + transform.translateX + (projected.x * transform.scale),
    y: bounds.top + transform.translateY + (projected.y * transform.scale),
  };
}

// Returns projection calibration.
function getProjectionCalibration(settingsGetter) {
  const debugSettings = settingsGetter?.()?.debug || {};
  const calibration = {
    zoomX: clampProjectionSetting(
      debugSettings.mapProjectionZoomX,
      WIKIMEDIA_WORLD_MAP_PROJECTION_ZOOM_X,
      0.1,
      3,
    ),
    zoomY: clampProjectionSetting(
      debugSettings.mapProjectionZoomY,
      WIKIMEDIA_WORLD_MAP_PROJECTION_ZOOM_Y,
      0.1,
      3,
    ),
    offsetX: clampProjectionSetting(
      debugSettings.mapProjectionOffsetX,
      WIKIMEDIA_WORLD_MAP_PROJECTION_OFFSET_X,
      -2.2,
      2.2,
    ),
    offsetY: clampProjectionSetting(
      debugSettings.mapProjectionOffsetY,
      WIKIMEDIA_WORLD_MAP_PROJECTION_OFFSET_Y,
      -2.2,
      2.2,
    ),
  };
  lastStatsMapProjectionCalibration = calibration;
  return calibration;
}

// Returns projection calibration lock state.
function getProjectionCalibrationLockState(settingsGetter) {
  const debugSettings = settingsGetter?.()?.debug || {};
  if (typeof debugSettings.mapProjectionCalibrationLocked === "boolean") {
    return debugSettings.mapProjectionCalibrationLocked;
  }
  return true;
}

// Parses theme rgb value.
function parseThemeRgbValue(colorValue) {
  const normalizedColor = typeof colorValue === "string" ? colorValue.trim() : "";
  if (!normalizedColor) return null;

  const hexMatch = normalizedColor.match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i);
  if (hexMatch) {
    const compactHex = hexMatch[1];
    const expandedHex = compactHex.length === 3
      ? compactHex.split("").map((char) => char + char).join("")
      : compactHex;
    return {
      r: Number.parseInt(expandedHex.slice(0, 2), 16),
      g: Number.parseInt(expandedHex.slice(2, 4), 16),
      b: Number.parseInt(expandedHex.slice(4, 6), 16),
    };
  }

  const rgbMatch = normalizedColor.match(
    /^rgba?\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})(?:\s*,\s*[0-9.]+)?\s*\)$/i,
  );
  if (!rgbMatch) return null;

  return {
    r: Math.min(255, Number(rgbMatch[1])),
    g: Math.min(255, Number(rgbMatch[2])),
    b: Math.min(255, Number(rgbMatch[3])),
  };
}

// Returns stats heatmap theme rgb.
function getStatsHeatmapThemeRgb() {
  const rootStyles = window.getComputedStyle(document.documentElement);
  return (
    parseThemeRgbValue(rootStyles.getPropertyValue("--color-1")) ||
    parseThemeRgbValue(rootStyles.getPropertyValue("--header-text-color")) ||
    { r: 127, g: 128, b: 255 }
  );
}

// Builds stats heatmap gradient.
function buildStatsHeatmapGradient(themeRgb) {
  if (!themeRgb) {
    return {
      0.15: "rgba(48, 48, 48, 0.28)",
      0.45: "rgba(96, 96, 96, 0.5)",
      0.72: "rgba(160, 160, 160, 0.76)",
      1.0: "rgba(255, 255, 255, 0.95)",
    };
  }

  const { r, g, b } = themeRgb;
  return {
    0.12: `rgba(${r}, ${g}, ${b}, 0.18)`,
    0.35: `rgba(${r}, ${g}, ${b}, 0.36)`,
    0.62: `rgba(${r}, ${g}, ${b}, 0.62)`,
    0.82: `rgba(${r}, ${g}, ${b}, 0.82)`,
    1.0: `rgba(255, 255, 255, 0.96)`,
  };
}

// Returns heatmap display value.
function getHeatmapDisplayValue(rawValue, intensityScale = 1) {
  const numericValue = Math.max(1, Number(rawValue) || 1);
  return Math.max(1, Math.round(Math.sqrt(numericValue) * 10 * intensityScale));
}

// Handles clamp heatmap percent.
function clampHeatmapPercent(value, fallback) {
  const numericValue = Number(value);
  if (!Number.isFinite(numericValue)) return fallback;
  return Math.min(200, Math.max(40, Math.round(numericValue)));
}

// Handles clamp heatmap map zoom percent.
function clampHeatmapMapZoomPercent(value, fallback = DEFAULT_HEATMAP_MAP_ZOOM) {
  const numericValue = Number(value);
  if (!Number.isFinite(numericValue)) return fallback;
  return Math.min(MAX_HEATMAP_MAP_ZOOM, Math.max(MIN_HEATMAP_MAP_ZOOM, Math.round(numericValue)));
}

// Handles smoothstep.
function smoothstep(value) {
  const x = Math.min(1, Math.max(0, Number(value) || 0));
  return x * x * (3 - 2 * x);
}

// Returns selection zoom percent from area.
function getSelectionZoomPercentFromArea(selectionRect, bounds) {
  const selectionArea = Math.max(1, selectionRect.width * selectionRect.height);
  const boundsArea = Math.max(1, bounds.width * bounds.height);
  const areaRatio = Math.min(1, Math.max(0, selectionArea / boundsArea));
  const tinyRatio = HEATMAP_SELECTION_AREA_TINY_RATIO;
  const midRatio = HEATMAP_SELECTION_AREA_MID_RATIO;
  const largeRatio = HEATMAP_SELECTION_AREA_LARGE_RATIO;
  const safeAreaRatio = Math.min(largeRatio, Math.max(tinyRatio, areaRatio));

  if (!(tinyRatio < midRatio && midRatio < largeRatio)) {
    return clampHeatmapMapZoomPercent(HEATMAP_SELECTION_ZOOM_MID_AREA_PERCENT);
  }

  const interpolateZoom = (startRatio, endRatio, startZoom, endZoom) => {
    const span = endRatio - startRatio;
    if (!Number.isFinite(span) || span <= 0) return startZoom;
    const normalized = Math.min(1, Math.max(0, (safeAreaRatio - startRatio) / span));
    const eased = smoothstep(normalized);
    return startZoom + ((endZoom - startZoom) * eased);
  };

  let zoomPercent;
  if (safeAreaRatio <= midRatio) {
    zoomPercent = interpolateZoom(
      tinyRatio,
      midRatio,
      HEATMAP_SELECTION_ZOOM_TINY_AREA_PERCENT,
      HEATMAP_SELECTION_ZOOM_MID_AREA_PERCENT,
    );
  } else {
    zoomPercent = interpolateZoom(
      midRatio,
      largeRatio,
      HEATMAP_SELECTION_ZOOM_MID_AREA_PERCENT,
      HEATMAP_SELECTION_ZOOM_LARGE_AREA_PERCENT,
    );
  }

  return clampHeatmapMapZoomPercent(zoomPercent, HEATMAP_SELECTION_ZOOM_MID_AREA_PERCENT);
}

// Builds heatmap render config.
function buildHeatmapRenderConfig(width, height, controls = {}) {
  const intensityPercent = clampHeatmapPercent(
    controls.intensityPercent,
    DEFAULT_HEATMAP_INTENSITY,
  );
  const tightnessPercent = clampHeatmapPercent(
    controls.tightnessPercent,
    DEFAULT_HEATMAP_TIGHTNESS,
  );
  const pointSizePercent = clampHeatmapPercent(
    controls.pointSizePercent,
    DEFAULT_HEATMAP_POINT_SIZE,
  );
  const blurPercent = clampHeatmapPercent(
    controls.blurPercent,
    DEFAULT_HEATMAP_BLUR,
  );
  const tightnessRatio = tightnessPercent / 100;
  const pointSizeRatio = pointSizePercent / 100;
  const blurRatio = blurPercent / 100;
  const baseSize = Math.min(width, height);
  const radiusScale = 1.45 - (tightnessRatio * 0.9);
  const blurScale = 0.28 + (blurRatio * 0.52);

  return {
    intensityPercent,
    intensityScale: intensityPercent / 100,
    tightnessPercent,
    pointSizePercent,
    blurPercent,
    radius: Math.max(7, Math.round(baseSize * 0.03 * radiusScale)),
    blur: Math.max(0.18, Math.min(0.95, blurScale)),
    pointCoreSize: Math.max(2, Math.round((7 - tightnessRatio * 2.2) * pointSizeRatio)),
  };
}

// Returns heatmap map bounds.
function getHeatmapMapBounds(containerWidth, containerHeight) {
  if (!Number.isFinite(containerWidth) || !Number.isFinite(containerHeight)) {
    return {
      left: 0,
      top: 0,
      width: 0,
      height: 0,
    };
  }

  const containerAspectRatio = containerWidth / containerHeight;
  if (containerAspectRatio > WIKIMEDIA_WORLD_MAP_ASPECT_RATIO) {
    const mapHeight = containerHeight;
    const mapWidth = mapHeight * WIKIMEDIA_WORLD_MAP_ASPECT_RATIO;
    return {
      left: Math.round((containerWidth - mapWidth) / 2),
      top: 0,
      width: Math.round(mapWidth),
      height: Math.round(mapHeight),
    };
  }

  const mapWidth = containerWidth;
  const mapHeight = mapWidth / WIKIMEDIA_WORLD_MAP_ASPECT_RATIO;
  return {
    left: 0,
    top: Math.round((containerHeight - mapHeight) / 2),
    width: Math.round(mapWidth),
    height: Math.round(mapHeight),
  };
}

// Applies heatmap layer bounds.
function applyHeatmapLayerBounds(layerEl, bounds) {
  if (!layerEl || !bounds) return;
  layerEl.style.left = `${bounds.left}px`;
  layerEl.style.top = `${bounds.top}px`;
  layerEl.style.width = `${bounds.width}px`;
  layerEl.style.height = `${bounds.height}px`;
}

// Returns heatmap view transform.
function getHeatmapViewTransform(bounds, viewState = {}) {
  const zoomPercent = clampHeatmapMapZoomPercent(viewState.zoomPercent, DEFAULT_HEATMAP_MAP_ZOOM);
  const scale = zoomPercent / 100;
  const focusX = Math.min(1, Math.max(0, Number(viewState.focusX) || 0.5));
  const focusY = Math.min(1, Math.max(0, Number(viewState.focusY) || 0.5));
  const boundsWidth = Math.max(1, Number(bounds?.width) || 1);
  const boundsHeight = Math.max(1, Number(bounds?.height) || 1);

  let translateX = 0;
  let translateY = 0;
  if (scale > 1) {
    translateX = (boundsWidth / 2) - (focusX * boundsWidth * scale);
    translateY = (boundsHeight / 2) - (focusY * boundsHeight * scale);
  }

  return {
    scale,
    focusX,
    focusY,
    boundsWidth,
    boundsHeight,
    translateX,
    translateY,
  };
}

// Handles convert viewport rect to map rect.
function convertViewportRectToMapRect(bounds, selectionRect, viewState = {}) {
  const transform = getHeatmapViewTransform(bounds, viewState);
  const scale = Math.max(0.0001, transform.scale);
  const leftInBounds = Math.max(0, (selectionRect.left - bounds.left - transform.translateX) / scale);
  const topInBounds = Math.max(0, (selectionRect.top - bounds.top - transform.translateY) / scale);
  const rightInBounds = Math.min(
    transform.boundsWidth,
    ((selectionRect.left + selectionRect.width) - bounds.left - transform.translateX) / scale,
  );
  const bottomInBounds = Math.min(
    transform.boundsHeight,
    ((selectionRect.top + selectionRect.height) - bounds.top - transform.translateY) / scale,
  );

  return {
    left: Math.min(transform.boundsWidth, Math.max(0, leftInBounds)),
    top: Math.min(transform.boundsHeight, Math.max(0, topInBounds)),
    width: Math.max(0, rightInBounds - leftInBounds),
    height: Math.max(0, bottomInBounds - topInBounds),
  };
}

// Applies heatmap layer zoom.
function applyHeatmapLayerZoom(layerEl, bounds, viewState = {}) {
  if (!layerEl) return;
  const transform = getHeatmapViewTransform(
    {
      width: Math.max(1, Number(bounds?.width) || layerEl.clientWidth || 1),
      height: Math.max(1, Number(bounds?.height) || layerEl.clientHeight || 1),
    },
    viewState,
  );

  layerEl.style.transformOrigin = "0 0";
  layerEl.style.transform = `translate(${transform.translateX.toFixed(2)}px, ${transform.translateY.toFixed(2)}px) scale(${transform.scale.toFixed(3)})`;
}

// Applies basemap zoom by resizing and panning the image directly inside the frame.
function applyHeatmapBasemapZoom(basemapFrameEl, bounds, viewState = {}) {
  if (!basemapFrameEl) return;
  const basemapImageEl = basemapFrameEl.querySelector(".stats-heatmap-basemap");
  if (!basemapImageEl) return;

  const transform = getHeatmapViewTransform(
    {
      width: Math.max(1, Number(bounds?.width) || basemapFrameEl.clientWidth || 1),
      height: Math.max(1, Number(bounds?.height) || basemapFrameEl.clientHeight || 1),
    },
    viewState,
  );

  basemapFrameEl.style.transformOrigin = "0 0";
  basemapFrameEl.style.transform = "translate(0px, 0px) scale(1)";

  const renderedWidth = Math.max(1, transform.boundsWidth * transform.scale);
  const renderedHeight = Math.max(1, transform.boundsHeight * transform.scale);
  basemapImageEl.style.left = `${transform.translateX.toFixed(2)}px`;
  basemapImageEl.style.top = `${transform.translateY.toFixed(2)}px`;
  basemapImageEl.style.width = `${renderedWidth.toFixed(2)}px`;
  basemapImageEl.style.height = `${renderedHeight.toFixed(2)}px`;
}

// Returns heatmap focus coordinates.
function getHeatmapFocusCoordinates(viewState = {}) {
  const focusX = Math.min(1, Math.max(0, Number(viewState.focusX) || 0.5));
  const focusY = Math.min(1, Math.max(0, Number(viewState.focusY) || 0.5));
  return {
    latitude: (0.5 - focusY) * 180,
    longitude: (focusX - 0.5) * 360,
  };
}

// Formats heatmap coordinate.
function formatHeatmapCoordinate(value, positiveSuffix, negativeSuffix) {
  const absoluteValue = Math.abs(Number(value) || 0);
  const suffix = value >= 0 ? positiveSuffix : negativeSuffix;
  return `${absoluteValue.toFixed(2)}${suffix}`;
}

// Applies heatmap grid density.
function applyHeatmapGridDensity(gridLayerEl, viewState = {}) {
  if (!gridLayerEl) return;
  const zoomPercent = clampHeatmapMapZoomPercent(
    viewState.zoomPercent,
    DEFAULT_HEATMAP_MAP_ZOOM,
  );
  const zoomScale = Math.max(1, zoomPercent / 100);
  const responsiveScale = Math.pow(zoomScale, HEATMAP_GRID_ZOOM_RESPONSE_EXPONENT);
  const cellSizeX = Math.max(
    HEATMAP_GRID_MIN_CELL_SIZE,
    HEATMAP_GRID_BASE_CELL_SIZE_X / responsiveScale,
  );
  const cellSizeY = Math.max(
    HEATMAP_GRID_MIN_CELL_SIZE,
    HEATMAP_GRID_BASE_CELL_SIZE_Y / responsiveScale,
  );
  gridLayerEl.style.setProperty("--stats-heatmap-grid-cell-size-x", `${cellSizeX.toFixed(2)}px`);
  gridLayerEl.style.setProperty("--stats-heatmap-grid-cell-size-y", `${cellSizeY.toFixed(2)}px`);
}

// Renders stats heatmap points.
function renderStatsHeatmapPoints(pointsMountEl, points, width, height, themeRgb, renderConfig) {
  if (!pointsMountEl) return;
  pointsMountEl.replaceChildren();
  if (!Array.isArray(points) || points.length === 0) return;

  const fragment = document.createDocumentFragment();
  points.forEach((point) => {
    const projected = projectGeoPoint(
      point.latitude,
      point.longitude,
      width,
      height,
      WIKIMEDIA_WORLD_MAP_PROJECTION_BOUNDS,
      renderConfig.projectionCalibration,
    );
    const dotEl = document.createElement("div");
    dotEl.className = "stats-heatmap-point";
    const pointKey = typeof point.pointKey === "string" ? point.pointKey : "";
    if (pointKey) {
      dotEl.dataset.pointKey = pointKey;
    }
    const size = Math.max(
      renderConfig.pointCoreSize,
      Math.min(
        14,
        Math.round(renderConfig.pointCoreSize + Math.sqrt(Number(point.value) || 1) * 0.32),
      ),
    );
    dotEl.style.left = `${projected.x}px`;
    dotEl.style.top = `${projected.y}px`;
    dotEl.style.width = `${size}px`;
    dotEl.style.height = `${size}px`;
    dotEl.style.backgroundColor = `rgba(${themeRgb.r}, ${themeRgb.g}, ${themeRgb.b}, 0.9)`;
    dotEl.style.boxShadow = `0 0 0 1px rgba(255,255,255,0.8), 0 0 ${Math.max(8, size * 1.8)}px rgba(${themeRgb.r}, ${themeRgb.g}, ${themeRgb.b}, 0.38)`;
    dotEl.title = point.valueLabel
      ? `${point.label} (${point.valueLabel})`
      : `${point.label} (${point.value})`;
    fragment.appendChild(dotEl);
  });
  pointsMountEl.appendChild(fragment);
}

// Returns packet payload length.
function getPacketPayloadLength(packetInfo) {
  const payloadLength = Number(
    packetInfo?.["raw.data"]?.["payload.len"] ??
    packetInfo?.["Raw data"]?.["payload.len"] ??
    packetInfo?.["Raw data"]?.["Payload Length"]
  );
  if (!Number.isFinite(payloadLength) || payloadLength <= 0) return 0;
  return payloadLength;
}

// Returns capture packet list.
function getCapturePacketList(capturedPackets) {
  const packetList = [];
  if (!capturedPackets || !capturedPackets["host"]) return packetList;
  for (const hostKey of Object.keys(capturedPackets["host"])) {
    const hostPackets = capturedPackets["host"][hostKey];
    if (!Array.isArray(hostPackets)) continue;
    hostPackets.forEach((packet) => packetList.push(packet));
  }
  return packetList;
}

// Builds heatmap stats from packet list.
function buildHeatmapStatsFromPacketList(packetList, valueMode = HEATMAP_METRIC_PACKETS) {
  const heatmapPointsByCoordinate = new Map();
  const internetHosts = new Set();
  let heatmapPacketHits = 0;
  let heatmapBytes = 0;

  const packets = Array.isArray(packetList) ? packetList : [];
  packets.forEach((packet) => {
    const packetInfo = packet?.["packet.info"];
    const extraInfo = packet?.["extra.info"] || {};
    if (!packetInfo) return;

    const payloadLength = getPacketPayloadLength(packetInfo);
    const networkData = extraInfo?.["Traits"]?.["Network Data"];
    if (!networkData) return;

    [["ip.src", "Source IP"], ["ip.dst", "Destination IP"]].forEach(([dotSide, legacySide]) => {
      const locationData = networkData?.[dotSide]?.["Location"] ?? networkData?.[legacySide]?.["Location"];
      const city = normalizeStatsTextValue(locationData?.["City"]);
      const country = normalizeStatsTextValue(locationData?.["Country"]);
      const ipAddress =
        dotSide === "ip.src"
          ? packetInfo?.["IP"]?.["ip.src.addr"] ?? packetInfo?.["IP"]?.["Source IP"]
          : packetInfo?.["IP"]?.["ip.dst.addr"] ?? packetInfo?.["IP"]?.["Destination IP"];
      const mappedPoint = collectInternetLocationPoint(locationData, city || country, ipAddress);
      if (!mappedPoint) return;

      heatmapPacketHits += 1;
      heatmapBytes += payloadLength;

      const nextValue = valueMode === HEATMAP_METRIC_BYTES ? payloadLength : 1;
      if (nextValue <= 0) {
        if (mappedPoint.ipAddress) internetHosts.add(mappedPoint.ipAddress);
        return;
      }

      const coordinateKey = `${mappedPoint.latitude.toFixed(4)},${mappedPoint.longitude.toFixed(4)}`;
      const existingPoint = heatmapPointsByCoordinate.get(coordinateKey);
      if (existingPoint) {
        existingPoint.value += nextValue;
        if (mappedPoint.ipAddress) {
          existingPoint.ipAddresses.add(mappedPoint.ipAddress);
        }
        if (!existingPoint.city && mappedPoint.city) {
          existingPoint.city = mappedPoint.city;
        }
        if (!existingPoint.country && mappedPoint.country) {
          existingPoint.country = mappedPoint.country;
        }
      } else {
        const ipAddresses = new Set();
        if (mappedPoint.ipAddress) {
          ipAddresses.add(mappedPoint.ipAddress);
        }
        heatmapPointsByCoordinate.set(coordinateKey, {
          pointKey: coordinateKey,
          latitude: mappedPoint.latitude,
          longitude: mappedPoint.longitude,
          label: mappedPoint.label,
          city: mappedPoint.city,
          country: mappedPoint.country,
          value: nextValue,
          ipAddresses,
        });
      }

      if (mappedPoint.ipAddress) {
        internetHosts.add(mappedPoint.ipAddress);
      }
    });
  });

  return {
    heatmapPoints: [...heatmapPointsByCoordinate.values()].map((point) => ({
      ...point,
      ipAddresses: [...(point.ipAddresses || [])].sort(),
    })).sort((a, b) => b.value - a.value),
    heatmapPacketHits,
    heatmapBytes,
    internetHostCount: internetHosts.size,
  };
}

// Handles highlight heatmap point.
function highlightHeatmapPoint(pointsMountEl, pointKey) {
  if (!pointsMountEl) return;
  const pointEls = pointsMountEl.querySelectorAll(".stats-heatmap-point");
  pointEls.forEach((pointEl) => pointEl.classList.remove("stats-heatmap-point-blink"));
  if (!pointKey) return;
  const activePointEl = pointsMountEl.querySelector(`.stats-heatmap-point[data-point-key="${pointKey}"]`);
  if (activePointEl) {
    activePointEl.classList.add("stats-heatmap-point-blink");
  }
}

// Renders stats heatmap.
function renderStatsHeatmap(
  mapContainerEl,
  basemapFrameEl,
  gridLayerEl,
  heatmapMountEl,
  pointsMountEl,
  points,
  projectionCalibration,
  controls = {},
  viewState = {},
  options = {},
) {
  if (!heatmapMountEl) return;

  heatmapMountEl.replaceChildren();
  if (pointsMountEl) {
    pointsMountEl.replaceChildren();
  }
  if (!Array.isArray(points) || points.length === 0) return;

  const width = Math.max(320, mapContainerEl?.clientWidth || 0);
  const height = Math.max(220, mapContainerEl?.clientHeight || 0);
  const mapBounds = getHeatmapMapBounds(width, height);
  const basemapImageEl = basemapFrameEl?.querySelector(".stats-heatmap-basemap");
  if (basemapImageEl) {
    const basemapZoomPercent = options?.preferLowResBasemap
      ? HEATMAP_ZOOM_TRANSITION_RASTER_PERCENT
      : viewState?.zoomPercent;
    void applyThemedStatsBasemapImage(basemapImageEl, {
      zoomPercent: basemapZoomPercent,
      boundsWidth: mapBounds.width,
      boundsHeight: mapBounds.height,
    });
  }
  applyHeatmapLayerBounds(basemapFrameEl, mapBounds);
  applyHeatmapLayerBounds(gridLayerEl, mapBounds);
  applyHeatmapLayerBounds(heatmapMountEl, mapBounds);
  applyHeatmapLayerBounds(pointsMountEl, mapBounds);
  applyHeatmapGridDensity(gridLayerEl, viewState);
  applyHeatmapBasemapZoom(basemapFrameEl, mapBounds, viewState);
  applyHeatmapLayerZoom(gridLayerEl, mapBounds, viewState);
  applyHeatmapLayerZoom(heatmapMountEl, mapBounds, viewState);
  applyHeatmapLayerZoom(pointsMountEl, mapBounds, viewState);

  const renderConfig = buildHeatmapRenderConfig(width, height, controls);
  const projectedData = points.map((point) => {
    const projected = projectGeoPoint(
      point.latitude,
      point.longitude,
      mapBounds.width,
      mapBounds.height,
      WIKIMEDIA_WORLD_MAP_PROJECTION_BOUNDS,
      projectionCalibration,
    );
    return {
      x: projected.x,
      y: projected.y,
      value: getHeatmapDisplayValue(point.value, renderConfig.intensityScale),
    };
  });

  const themeRgb = getStatsHeatmapThemeRgb();
  const maxValue = projectedData.reduce(
    (currentMax, point) => Math.max(currentMax, point.value),
    1,
  );

  const heatmapInstance = h337.create({
    container: heatmapMountEl,
    radius: renderConfig.radius,
    blur: renderConfig.blur,
    maxOpacity: 0.95,
    minOpacity: 0.1,
    gradient: buildStatsHeatmapGradient(themeRgb),
    backgroundColor: "rgba(0, 0, 0, 0)",
  });
  heatmapInstance.setData({
    min: 1,
    max: maxValue,
    data: projectedData,
  });

  renderStatsHeatmapPoints(
    pointsMountEl,
    points,
    mapBounds.width,
    mapBounds.height,
    themeRgb,
    {
      ...renderConfig,
      projectionCalibration,
    },
  );
}

// Creates stats heatmap section.
function createStatsHeatmapSection({
  documentRef,
  stats,
  getCapturedPackets,
  getFilteredPackets,
  getProjectionCalibrationSettings,
  getCurrentSettings,
  applyStatsQuery,
}) {
  const section = documentRef.createElement("div");
  section.className = "stats-section";

  const heading = documentRef.createElement("div");
  heading.className = "stats-section-title";
  heading.textContent = "Internet Heatmap";
  section.appendChild(heading);

  const shell = documentRef.createElement("div");
  shell.className = "stats-heatmap-shell";

  const controlsEl = documentRef.createElement("div");
  controlsEl.className = "stats-heatmap-controls";

  const controlsToolbarEl = documentRef.createElement("div");
  controlsToolbarEl.className = "stats-heatmap-toolbar";

  const mapZoomControlEl = documentRef.createElement("label");
  mapZoomControlEl.className = "stats-heatmap-mapzoom";
  mapZoomControlEl.innerHTML = "<span>Zoom</span>";
  const mapZoomInputEl = documentRef.createElement("input");
  mapZoomInputEl.type = "range";
  mapZoomInputEl.className = "stats-heatmap-mapzoom-input";
  mapZoomInputEl.min = String(MIN_HEATMAP_MAP_ZOOM);
  mapZoomInputEl.max = String(MAX_HEATMAP_MAP_ZOOM);
  mapZoomInputEl.step = String(HEATMAP_MAP_ZOOM_SLIDER_STEP);
  mapZoomInputEl.value = String(DEFAULT_HEATMAP_MAP_ZOOM);
  const mapZoomValueEl = documentRef.createElement("strong");
  mapZoomValueEl.className = "stats-heatmap-control-value";
  mapZoomControlEl.appendChild(mapZoomInputEl);
  mapZoomControlEl.appendChild(mapZoomValueEl);

  const toggleControlsBtn = documentRef.createElement("button");
  toggleControlsBtn.type = "button";
  toggleControlsBtn.className = "stats-heatmap-rollup";
  toggleControlsBtn.textContent = "Hide Sliders";
  controlsToolbarEl.appendChild(toggleControlsBtn);
  shell.appendChild(controlsToolbarEl);

  const scopeControlEl = documentRef.createElement("label");
  scopeControlEl.className = "stats-heatmap-control";
  scopeControlEl.innerHTML = "<span>Aggregate By</span>";
  const scopeInputEl = documentRef.createElement("select");
  scopeInputEl.innerHTML = `
    <option value="${HEATMAP_SCOPE_CAPTURE}">Entire Capture</option>
    <option value="${HEATMAP_SCOPE_FILTERED}">Filtered Packets</option>
  `;
  scopeControlEl.appendChild(scopeInputEl);

  const metricControlEl = documentRef.createElement("label");
  metricControlEl.className = "stats-heatmap-control";
  metricControlEl.innerHTML = "<span>Intensity By</span>";
  const metricInputEl = documentRef.createElement("select");
  metricInputEl.innerHTML = `
    <option value="${HEATMAP_METRIC_PACKETS}">Packets</option>
    <option value="${HEATMAP_METRIC_BYTES}">Bytes</option>
  `;
  metricControlEl.appendChild(metricInputEl);

  const intensityControlEl = documentRef.createElement("label");
  intensityControlEl.className = "stats-heatmap-control";
  intensityControlEl.innerHTML = "<span>Intensity</span>";
  const intensityInputEl = documentRef.createElement("input");
  intensityInputEl.type = "range";
  intensityInputEl.min = "40";
  intensityInputEl.max = "200";
  intensityInputEl.step = "5";
  intensityInputEl.value = String(DEFAULT_HEATMAP_INTENSITY);
  const intensityValueEl = documentRef.createElement("strong");
  intensityValueEl.className = "stats-heatmap-control-value";
  intensityControlEl.appendChild(intensityInputEl);
  intensityControlEl.appendChild(intensityValueEl);

  const pointSizeControlEl = documentRef.createElement("label");
  pointSizeControlEl.className = "stats-heatmap-control";
  pointSizeControlEl.innerHTML = "<span>Point Size</span>";
  const pointSizeInputEl = documentRef.createElement("input");
  pointSizeInputEl.type = "range";
  pointSizeInputEl.min = "40";
  pointSizeInputEl.max = "200";
  pointSizeInputEl.step = "5";
  pointSizeInputEl.value = String(DEFAULT_HEATMAP_POINT_SIZE);
  const pointSizeValueEl = documentRef.createElement("strong");
  pointSizeValueEl.className = "stats-heatmap-control-value";
  pointSizeControlEl.appendChild(pointSizeInputEl);
  pointSizeControlEl.appendChild(pointSizeValueEl);

  const tightnessControlEl = documentRef.createElement("label");
  tightnessControlEl.className = "stats-heatmap-control";
  tightnessControlEl.innerHTML = "<span>Tightness</span>";
  const tightnessInputEl = documentRef.createElement("input");
  tightnessInputEl.type = "range";
  tightnessInputEl.min = "40";
  tightnessInputEl.max = "200";
  tightnessInputEl.step = "5";
  tightnessInputEl.value = String(DEFAULT_HEATMAP_TIGHTNESS);
  const tightnessValueEl = documentRef.createElement("strong");
  tightnessValueEl.className = "stats-heatmap-control-value";
  tightnessControlEl.appendChild(tightnessInputEl);
  tightnessControlEl.appendChild(tightnessValueEl);

  const blurControlEl = documentRef.createElement("label");
  blurControlEl.className = "stats-heatmap-control";
  blurControlEl.innerHTML = "<span>Blur</span>";
  const blurInputEl = documentRef.createElement("input");
  blurInputEl.type = "range";
  blurInputEl.min = "40";
  blurInputEl.max = "200";
  blurInputEl.step = "5";
  blurInputEl.value = String(DEFAULT_HEATMAP_BLUR);
  const blurValueEl = documentRef.createElement("strong");
  blurValueEl.className = "stats-heatmap-control-value";
  blurControlEl.appendChild(blurInputEl);
  blurControlEl.appendChild(blurValueEl);

  const calibrationHeadingEl = documentRef.createElement("div");
  calibrationHeadingEl.className = "stats-heatmap-controls-heading";
  calibrationHeadingEl.textContent = "Projection Calibration (Persistent)";

  const calibrationLockControlEl = documentRef.createElement("label");
  calibrationLockControlEl.className = "stats-heatmap-lock-row";
  const calibrationLockInputEl = documentRef.createElement("input");
  calibrationLockInputEl.type = "checkbox";
  const calibrationLockTextEl = documentRef.createElement("span");
  calibrationLockTextEl.textContent = "Lock point calibration (debug)";
  calibrationLockControlEl.appendChild(calibrationLockInputEl);
  calibrationLockControlEl.appendChild(calibrationLockTextEl);

  const zoomXControlEl = documentRef.createElement("label");
  zoomXControlEl.className = "stats-heatmap-control";
  zoomXControlEl.innerHTML = "<span>Zoom X</span>";
  const zoomXInputEl = documentRef.createElement("input");
  zoomXInputEl.type = "range";
  zoomXInputEl.min = "0.1";
  zoomXInputEl.max = "3";
  zoomXInputEl.step = "0.01";
  const zoomXValueEl = documentRef.createElement("strong");
  zoomXValueEl.className = "stats-heatmap-control-value";
  zoomXControlEl.appendChild(zoomXInputEl);
  zoomXControlEl.appendChild(zoomXValueEl);

  const zoomYControlEl = documentRef.createElement("label");
  zoomYControlEl.className = "stats-heatmap-control";
  zoomYControlEl.innerHTML = "<span>Zoom Y</span>";
  const zoomYInputEl = documentRef.createElement("input");
  zoomYInputEl.type = "range";
  zoomYInputEl.min = "0.1";
  zoomYInputEl.max = "3";
  zoomYInputEl.step = "0.01";
  const zoomYValueEl = documentRef.createElement("strong");
  zoomYValueEl.className = "stats-heatmap-control-value";
  zoomYControlEl.appendChild(zoomYInputEl);
  zoomYControlEl.appendChild(zoomYValueEl);

  const offsetXControlEl = documentRef.createElement("label");
  offsetXControlEl.className = "stats-heatmap-control";
  offsetXControlEl.innerHTML = "<span>Offset X</span>";
  const offsetXInputEl = documentRef.createElement("input");
  offsetXInputEl.type = "range";
  offsetXInputEl.min = "-2.2";
  offsetXInputEl.max = "2.2";
  offsetXInputEl.step = "0.01";
  const offsetXValueEl = documentRef.createElement("strong");
  offsetXValueEl.className = "stats-heatmap-control-value";
  offsetXControlEl.appendChild(offsetXInputEl);
  offsetXControlEl.appendChild(offsetXValueEl);

  const offsetYControlEl = documentRef.createElement("label");
  offsetYControlEl.className = "stats-heatmap-control";
  offsetYControlEl.innerHTML = "<span>Offset Y</span>";
  const offsetYInputEl = documentRef.createElement("input");
  offsetYInputEl.type = "range";
  offsetYInputEl.min = "-2.2";
  offsetYInputEl.max = "2.2";
  offsetYInputEl.step = "0.01";
  const offsetYValueEl = documentRef.createElement("strong");
  offsetYValueEl.className = "stats-heatmap-control-value";
  offsetYControlEl.appendChild(offsetYInputEl);
  offsetYControlEl.appendChild(offsetYValueEl);

  const resetControlsBtn = documentRef.createElement("button");
  resetControlsBtn.type = "button";
  resetControlsBtn.className = "stats-heatmap-reset";
  resetControlsBtn.textContent = "Reset";

  controlsEl.appendChild(scopeControlEl);
  controlsEl.appendChild(metricControlEl);
  controlsEl.appendChild(intensityControlEl);
  controlsEl.appendChild(pointSizeControlEl);
  controlsEl.appendChild(tightnessControlEl);
  controlsEl.appendChild(blurControlEl);
  controlsEl.appendChild(calibrationHeadingEl);
  controlsEl.appendChild(calibrationLockControlEl);
  controlsEl.appendChild(resetControlsBtn);
  controlsEl.appendChild(zoomXControlEl);
  controlsEl.appendChild(zoomYControlEl);
  controlsEl.appendChild(offsetXControlEl);
  controlsEl.appendChild(offsetYControlEl);
  shell.appendChild(controlsEl);

  const mapEl = documentRef.createElement("div");
  mapEl.className = "stats-heatmap-map";

  const basemapFrameEl = documentRef.createElement("div");
  basemapFrameEl.className = "stats-heatmap-basemap-frame";
  const basemapEl = documentRef.createElement("img");
  basemapEl.className = "stats-heatmap-basemap";
  basemapEl.src = WIKIMEDIA_WORLD_MAP_ASSET_PATH;
  basemapEl.alt = "World map basemap";
  void applyThemedStatsBasemapImage(basemapEl);
  basemapFrameEl.appendChild(basemapEl);
  mapEl.appendChild(basemapFrameEl);

  const gridLayerEl = documentRef.createElement("div");
  gridLayerEl.className = "stats-heatmap-grid";
  mapEl.appendChild(gridLayerEl);

  const mapCoordinatesEl = documentRef.createElement("div");
  mapCoordinatesEl.className = "stats-heatmap-coordinates";
  mapCoordinatesEl.textContent = "Target 0.00N, 0.00E";
  mapEl.appendChild(mapCoordinatesEl);

  mapEl.appendChild(mapZoomControlEl);

  const latitudeLabels = [
    { className: "north", text: "90N" },
    { className: "equator", text: "EQ" },
    { className: "south", text: "90S" },
  ];
  latitudeLabels.forEach((labelConfig) => {
    const labelEl = documentRef.createElement("div");
    labelEl.className = `stats-heatmap-axis stats-heatmap-axis-${labelConfig.className}`;
    labelEl.textContent = labelConfig.text;
    mapEl.appendChild(labelEl);
  });

  const longitudeLabels = [
    { className: "west", text: "180W" },
    { className: "center", text: "0" },
    { className: "east", text: "180E" },
  ];
  longitudeLabels.forEach((labelConfig) => {
    const labelEl = documentRef.createElement("div");
    labelEl.className = `stats-heatmap-axis stats-heatmap-axis-${labelConfig.className}`;
    labelEl.textContent = labelConfig.text;
    mapEl.appendChild(labelEl);
  });

  const heatmapLayerEl = documentRef.createElement("div");
  heatmapLayerEl.className = "stats-heatmap-layer";
  mapEl.appendChild(heatmapLayerEl);

  const pointLayerEl = documentRef.createElement("div");
  pointLayerEl.className = "stats-heatmap-points";
  mapEl.appendChild(pointLayerEl);

  const selectionLayerEl = documentRef.createElement("div");
  selectionLayerEl.className = "stats-heatmap-selection";
  selectionLayerEl.hidden = true;
  mapEl.appendChild(selectionLayerEl);

  const zoomTintEl = documentRef.createElement("div");
  zoomTintEl.className = "stats-heatmap-zoom-tint";
  mapEl.appendChild(zoomTintEl);

  const pixelMaskEl = documentRef.createElement("div");
  pixelMaskEl.className = "stats-heatmap-pixel-mask";
  pixelMaskEl.hidden = true;
  const pixelMaskSegments = {
    top: documentRef.createElement("div"),
    left: documentRef.createElement("div"),
    right: documentRef.createElement("div"),
    bottom: documentRef.createElement("div"),
  };
  Object.values(pixelMaskSegments).forEach((segmentEl) => {
    segmentEl.className = "stats-heatmap-pixel-segment";
    pixelMaskEl.appendChild(segmentEl);
  });
  mapEl.appendChild(pixelMaskEl);

  shell.appendChild(mapEl);

  const summaryEl = documentRef.createElement("div");
  summaryEl.className = "stats-heatmap-summary";
  shell.appendChild(summaryEl);

  const locationsSectionEl = documentRef.createElement("div");
  locationsSectionEl.className = "stats-section";
  const locationsTitleEl = documentRef.createElement("div");
  locationsTitleEl.className = "stats-section-title";
  locationsTitleEl.textContent = "Most Active Mapped Locations";
  const locationsListEl = documentRef.createElement("div");
  locationsListEl.className = "stats-tag-list";
  locationsSectionEl.appendChild(locationsTitleEl);
  locationsSectionEl.appendChild(locationsListEl);
  shell.appendChild(locationsSectionEl);

  section.appendChild(shell);

  let selectedPointKey = null;
  let controlsCollapsed = true;
  let projectionCalibration =
    lastStatsMapProjectionCalibration || getProjectionCalibrationSettings();
  let calibrationLocked = getProjectionCalibrationLockState(getCurrentSettings);
  let persistCalibrationTimeoutId = null;
  let mapViewState = {
    zoomPercent: DEFAULT_HEATMAP_MAP_ZOOM,
    focusX: 0.5,
    focusY: 0.5,
  };
  let dragSelectionState = null;
  let selectionAnimating = false;
  let mapZoomInteractionActive = false;
  let mapZoomVisualTransitionToken = 0;
  let mapZoomVisualTransitionActive = false;
  let lastRenderedZoomPercent = DEFAULT_HEATMAP_MAP_ZOOM;
  let lastClickedLocationPointKey = null;
  let hoverAimState = null;
  let lockedCoordinate = null;
  let queuedLocationFilterPoint = null;
  let activeHeatmapData = {
    heatmapPoints: Array.isArray(stats?.heatmapPoints) ? stats.heatmapPoints : [],
    heatmapPacketHits: Number(stats?.heatmapPacketHits) || 0,
    heatmapBytes: 0,
    internetHostCount: Number(stats?.internetHostCount) || 0,
  };

  const toCalibrationLabel = (value) => Number(value).toFixed(2);
  const cloneSettings = (value) => {
    try {
      return JSON.parse(JSON.stringify(value || {}));
    } catch {
      return {};
    }
  };

  const getProjectionControlState = () => ({
    zoomX: clampProjectionSetting(
      zoomXInputEl.value,
      WIKIMEDIA_WORLD_MAP_PROJECTION_ZOOM_X,
      0.1,
      3,
    ),
    zoomY: clampProjectionSetting(
      zoomYInputEl.value,
      WIKIMEDIA_WORLD_MAP_PROJECTION_ZOOM_Y,
      0.1,
      3,
    ),
    offsetX: clampProjectionSetting(
      offsetXInputEl.value,
      WIKIMEDIA_WORLD_MAP_PROJECTION_OFFSET_X,
      -2.2,
      2.2,
    ),
    offsetY: clampProjectionSetting(
      offsetYInputEl.value,
      WIKIMEDIA_WORLD_MAP_PROJECTION_OFFSET_Y,
      -2.2,
      2.2,
    ),
  });

  const applyProjectionControlsFromCalibration = (calibration) => {
    zoomXInputEl.value = String(calibration.zoomX);
    zoomYInputEl.value = String(calibration.zoomY);
    offsetXInputEl.value = String(calibration.offsetX);
    offsetYInputEl.value = String(calibration.offsetY);
  };

  const updateCalibrationControlEnabledState = () => {
    const disabled = calibrationLocked;
    zoomXInputEl.disabled = disabled;
    zoomYInputEl.disabled = disabled;
    offsetXInputEl.disabled = disabled;
    offsetYInputEl.disabled = disabled;
  };

  const persistProjectionCalibration = async () => {
    if (!window.settingsapi || typeof window.settingsapi.save !== "function") return;
    let currentSettings =
      typeof getCurrentSettings === "function" ? getCurrentSettings() : null;
    if (typeof window.settingsapi.get === "function") {
      try {
        currentSettings = await window.settingsapi.get();
      } catch {
        // Fall back to in-memory settings snapshot.
      }
    }
    const nextSettings = cloneSettings(currentSettings);
    if (!nextSettings.debug || typeof nextSettings.debug !== "object") {
      nextSettings.debug = {};
    }
    nextSettings.debug.mapProjectionZoomX = projectionCalibration.zoomX;
    nextSettings.debug.mapProjectionZoomY = projectionCalibration.zoomY;
    nextSettings.debug.mapProjectionOffsetX = projectionCalibration.offsetX;
    nextSettings.debug.mapProjectionOffsetY = projectionCalibration.offsetY;
    nextSettings.debug.mapProjectionCalibrationLocked = calibrationLocked;

    try {
      const savedSettings = await window.settingsapi.save(nextSettings);
      const savedDebug = savedSettings?.debug;
      if (!savedDebug || typeof savedDebug !== "object") return;
      projectionCalibration = {
        zoomX: clampProjectionSetting(
          savedDebug.mapProjectionZoomX,
          projectionCalibration.zoomX,
          0.1,
          3,
        ),
        zoomY: clampProjectionSetting(
          savedDebug.mapProjectionZoomY,
          projectionCalibration.zoomY,
          0.1,
          3,
        ),
        offsetX: clampProjectionSetting(
          savedDebug.mapProjectionOffsetX,
          projectionCalibration.offsetX,
          -2.2,
          2.2,
        ),
        offsetY: clampProjectionSetting(
          savedDebug.mapProjectionOffsetY,
          projectionCalibration.offsetY,
          -2.2,
          2.2,
        ),
      };
      calibrationLocked =
        typeof savedDebug.mapProjectionCalibrationLocked === "boolean"
          ? savedDebug.mapProjectionCalibrationLocked
          : calibrationLocked;
      lastStatsMapProjectionCalibration = projectionCalibration;
      applyProjectionControlsFromCalibration(projectionCalibration);
      calibrationLockInputEl.checked = calibrationLocked;
      updateCalibrationControlEnabledState();
    } catch {
      // Ignore settings save failures in map interaction flow.
    }
  };

  const scheduleProjectionCalibrationSave = () => {
    if (persistCalibrationTimeoutId) {
      window.clearTimeout(persistCalibrationTimeoutId);
    }
    persistCalibrationTimeoutId = window.setTimeout(() => {
      persistCalibrationTimeoutId = null;
      void persistProjectionCalibration();
    }, 300);
  };

  applyProjectionControlsFromCalibration(projectionCalibration);

  const syncControlsCollapsedUi = () => {
    controlsEl.classList.toggle("stats-heatmap-controls-collapsed", controlsCollapsed);
    mapEl.classList.toggle("stats-heatmap-map-expanded", controlsCollapsed);
    toggleControlsBtn.textContent = controlsCollapsed ? "Show Sliders" : "Hide Sliders";
  };

  const getControlState = () => ({
    intensityPercent: clampHeatmapPercent(
      intensityInputEl.value,
      DEFAULT_HEATMAP_INTENSITY,
    ),
    pointSizePercent: clampHeatmapPercent(
      pointSizeInputEl.value,
      DEFAULT_HEATMAP_POINT_SIZE,
    ),
    tightnessPercent: clampHeatmapPercent(
      tightnessInputEl.value,
      DEFAULT_HEATMAP_TIGHTNESS,
    ),
    blurPercent: clampHeatmapPercent(
      blurInputEl.value,
      DEFAULT_HEATMAP_BLUR,
    ),
  });

  const getMapZoomState = () => ({
    zoomPercent: clampHeatmapMapZoomPercent(
      mapZoomInputEl.value,
      DEFAULT_HEATMAP_MAP_ZOOM,
    ),
    focusX: mapViewState.focusX,
    focusY: mapViewState.focusY,
  });

  const getCurrentMapBounds = () => {
    const width = Math.max(320, mapEl?.clientWidth || 0);
    const height = Math.max(220, mapEl?.clientHeight || 0);
    return getHeatmapMapBounds(width, height);
  };

  const setAimPosition = (x, y, visible = true) => {
    return;
  };

  const clearAimState = () => {
    hoverAimState = null;
    setAimPosition(0, 0, false);
  };

  const lockCoordinateTarget = (latitude, longitude) => {
    const lat = Number(latitude);
    const lon = Number(longitude);
    if (!Number.isFinite(lat) || !Number.isFinite(lon)) return;
    lockedCoordinate = {
      latitude: Math.min(90, Math.max(-90, lat)),
      longitude: Math.min(180, Math.max(-180, lon)),
    };
    hoverAimState = null;
  };

  const updateLockedAimPosition = () => {
    if (!lockedCoordinate) return;
    const bounds = getCurrentMapBounds();
    const point = convertGeoCoordinatesToViewportPoint(
      bounds,
      lockedCoordinate.latitude,
      lockedCoordinate.longitude,
      getMapZoomState(),
      getProjectionControlState(),
    );
    if (!point) return;
    setAimPosition(point.x, point.y, true);
  };

  const setCoordinateLabelFromState = (fallbackViewState) => {
    let latitude = null;
    let longitude = null;
    let prefix = "Target";

    if (lockedCoordinate) {
      latitude = lockedCoordinate.latitude;
      longitude = lockedCoordinate.longitude;
      prefix = "Locked";
    } else if (hoverAimState) {
      latitude = hoverAimState.latitude;
      longitude = hoverAimState.longitude;
      prefix = "Aim";
    } else {
      const focusCoordinates = getHeatmapFocusCoordinates(fallbackViewState || getMapZoomState());
      latitude = focusCoordinates.latitude;
      longitude = focusCoordinates.longitude;
    }

    mapCoordinatesEl.textContent = `${prefix} ${formatHeatmapCoordinate(latitude, "N", "S")}, ${formatHeatmapCoordinate(longitude, "E", "W")}`;
  };

  const resetSelectionBox = () => {
    dragSelectionState = null;
    pixelMaskEl.hidden = true;
    selectionLayerEl.hidden = true;
    selectionLayerEl.style.width = "0px";
    selectionLayerEl.style.height = "0px";
    selectionLayerEl.classList.remove(
      "stats-heatmap-selection-capture",
      "stats-heatmap-selection-blink",
      "stats-heatmap-selection-rush",
    );
    zoomTintEl.classList.remove("stats-heatmap-zoom-tint-pass");
    mapEl.classList.remove("stats-heatmap-selecting", "stats-heatmap-selection-animating");
  };

  const updatePixelMask = (selectionRect) => {
    const bounds = dragSelectionState?.bounds;
    if (!bounds || !selectionRect) {
      pixelMaskEl.hidden = true;
      return;
    }

    const topHeight = Math.max(0, selectionRect.top - bounds.top);
    const bottomY = selectionRect.top + selectionRect.height;
    const bottomHeight = Math.max(0, (bounds.top + bounds.height) - bottomY);
    const leftWidth = Math.max(0, selectionRect.left - bounds.left);
    const rightX = selectionRect.left + selectionRect.width;
    const rightWidth = Math.max(0, (bounds.left + bounds.width) - rightX);
    const middleHeight = Math.max(0, selectionRect.height);

    pixelMaskEl.hidden = false;

    pixelMaskSegments.top.style.left = `${bounds.left}px`;
    pixelMaskSegments.top.style.top = `${bounds.top}px`;
    pixelMaskSegments.top.style.width = `${bounds.width}px`;
    pixelMaskSegments.top.style.height = `${topHeight}px`;

    pixelMaskSegments.bottom.style.left = `${bounds.left}px`;
    pixelMaskSegments.bottom.style.top = `${bottomY}px`;
    pixelMaskSegments.bottom.style.width = `${bounds.width}px`;
    pixelMaskSegments.bottom.style.height = `${bottomHeight}px`;

    pixelMaskSegments.left.style.left = `${bounds.left}px`;
    pixelMaskSegments.left.style.top = `${selectionRect.top}px`;
    pixelMaskSegments.left.style.width = `${leftWidth}px`;
    pixelMaskSegments.left.style.height = `${middleHeight}px`;

    pixelMaskSegments.right.style.left = `${rightX}px`;
    pixelMaskSegments.right.style.top = `${selectionRect.top}px`;
    pixelMaskSegments.right.style.width = `${rightWidth}px`;
    pixelMaskSegments.right.style.height = `${middleHeight}px`;
  };

  const updateSelectionBox = (startX, startY, currentX, currentY) => {
    const bounds = dragSelectionState?.bounds;
    if (!bounds) return;
    const left = Math.max(bounds.left, Math.min(startX, currentX));
    const top = Math.max(bounds.top, Math.min(startY, currentY));
    const right = Math.min(bounds.left + bounds.width, Math.max(startX, currentX));
    const bottom = Math.min(bounds.top + bounds.height, Math.max(startY, currentY));
    const width = Math.max(0, right - left);
    const height = Math.max(0, bottom - top);
    const selectionRect = {
      left,
      top,
      width,
      height,
    };
    dragSelectionState.selectionRect = selectionRect;

    selectionLayerEl.hidden = false;
    selectionLayerEl.style.left = `${left}px`;
    selectionLayerEl.style.top = `${top}px`;
    selectionLayerEl.style.width = `${width}px`;
    selectionLayerEl.style.height = `${height}px`;
    updatePixelMask(selectionRect);
  };

  const getMapEventPoint = (event) => {
    const mapRect = mapEl.getBoundingClientRect();
    const x = event.clientX - mapRect.left;
    const y = event.clientY - mapRect.top;
    return { x, y };
  };

  const isMapZoomInteractionTarget = (eventTarget) => {
    if (!(eventTarget instanceof Element)) return false;
    return Boolean(eventTarget.closest(".stats-heatmap-mapzoom"));
  };

  const showSelectionRect = (bounds, selectionRect) => {
    dragSelectionState = {
      bounds,
      startX: selectionRect.left,
      startY: selectionRect.top,
      currentX: selectionRect.left + selectionRect.width,
      currentY: selectionRect.top + selectionRect.height,
      selectionRect,
    };
    selectionLayerEl.hidden = false;
    selectionLayerEl.style.left = `${selectionRect.left}px`;
    selectionLayerEl.style.top = `${selectionRect.top}px`;
    selectionLayerEl.style.width = `${selectionRect.width}px`;
    selectionLayerEl.style.height = `${selectionRect.height}px`;
    updatePixelMask(selectionRect);
  };

  const getSelectionFocusFromRect = (bounds, selectionRect, viewState = mapViewState) => {
    const mapRect = convertViewportRectToMapRect(bounds, selectionRect, viewState);
    return {
      focusX: Math.min(
        1,
        Math.max(0, (mapRect.left + (mapRect.width / 2)) / Math.max(1, bounds.width)),
      ),
      focusY: Math.min(
        1,
        Math.max(0, (mapRect.top + (mapRect.height / 2)) / Math.max(1, bounds.height)),
      ),
      mapRect,
    };
  };

  const buildLocationSelectionRect = (bounds, centerX, centerY) => {
    const aspectRatio =
      HEATMAP_LOCATION_SELECTION_ASPECT_WIDTH / HEATMAP_LOCATION_SELECTION_ASPECT_HEIGHT;
    let width = Math.max(120, Math.min(bounds.width / 3, bounds.height * 0.42 * aspectRatio));
    let height = width / aspectRatio;
    if (height > bounds.height * 0.42) {
      height = bounds.height * 0.42;
      width = height * aspectRatio;
    }
    width = Math.max(60, width * HEATMAP_LOCATION_SELECTION_SIZE_SCALE);
    height = Math.max(34, height * HEATMAP_LOCATION_SELECTION_SIZE_SCALE);
    const maxLeft = (bounds.left + bounds.width) - width;
    const maxTop = (bounds.top + bounds.height) - height;
    return {
      left: Math.max(bounds.left, Math.min(centerX - (width / 2), maxLeft)),
      top: Math.max(bounds.top, Math.min(centerY - (height / 2), maxTop)),
      width,
      height,
    };
  };

  const applySelectionZoom = () => {
    if (!dragSelectionState) return;
    const bounds = dragSelectionState.bounds;
    const selectionWidth = Math.abs(dragSelectionState.currentX - dragSelectionState.startX);
    const selectionHeight = Math.abs(dragSelectionState.currentY - dragSelectionState.startY);
    if (selectionWidth < HEATMAP_SELECTION_MIN_PIXELS || selectionHeight < HEATMAP_SELECTION_MIN_PIXELS) {
      return;
    }

    const selectionRect = dragSelectionState.selectionRect || {
      left: Math.min(dragSelectionState.startX, dragSelectionState.currentX),
      top: Math.min(dragSelectionState.startY, dragSelectionState.currentY),
      width: selectionWidth,
      height: selectionHeight,
    };
    const focus = getSelectionFocusFromRect(bounds, selectionRect, getMapZoomState());
    return {
      selectionRect,
      focusX: focus.focusX,
      focusY: focus.focusY,
      targetZoomPercent: getSelectionZoomPercentFromArea(focus.mapRect, bounds),
    };
  };

  const waitForSelectionAnimation = (durationMs) =>
    new Promise((resolve) => {
      window.setTimeout(resolve, durationMs);
    });

  const waitForMapZoomTransition = () =>
    new Promise((resolve) => {
      const fallbackTimeout = window.setTimeout(resolve, HEATMAP_ZOOM_SETTLE_MS + 80);
      const onTransitionEnd = (event) => {
        if (event?.propertyName !== "transform") return;
        window.clearTimeout(fallbackTimeout);
        pointLayerEl.removeEventListener("transitionend", onTransitionEnd);
        resolve();
      };
      pointLayerEl.addEventListener("transitionend", onTransitionEnd);
    });

  const beginMapZoomVisualTransition = () => {
    mapZoomVisualTransitionActive = true;
    mapEl.classList.add("stats-heatmap-zooming");
    mapZoomVisualTransitionToken += 1;
    return mapZoomVisualTransitionToken;
  };

  const endMapZoomVisualTransition = (transitionToken) => {
    if (transitionToken !== mapZoomVisualTransitionToken) return;
    mapZoomVisualTransitionActive = false;
    mapEl.classList.remove("stats-heatmap-zooming");
    // Refresh once at settled zoom so basemap raster updates at final resolution.
    render(false);
  };

  const animateSelectionZoom = async ({
    bounds,
    selectionRect,
    targetZoomPercent,
    focusX,
    focusY,
  }) => {
    if (selectionAnimating || !bounds || !selectionRect) return;

    selectionAnimating = true;
    showSelectionRect(bounds, selectionRect);
    mapEl.classList.add("stats-heatmap-selection-animating");
    mapEl.classList.remove("stats-heatmap-selecting");
    selectionLayerEl.classList.add("stats-heatmap-selection-capture");
    await waitForSelectionAnimation(HEATMAP_SELECTION_DRAW_MS);
    selectionLayerEl.classList.remove("stats-heatmap-selection-capture");
    selectionLayerEl.classList.add("stats-heatmap-selection-blink");
    await waitForSelectionAnimation(HEATMAP_SELECTION_BLINK_MS);
    selectionLayerEl.classList.remove("stats-heatmap-selection-blink");
    selectionLayerEl.style.setProperty("--stats-heatmap-selection-rush-duration", `${HEATMAP_SELECTION_RUSH_MS}ms`);
    zoomTintEl.style.setProperty("--stats-heatmap-zoom-tint-duration", `${HEATMAP_SELECTION_RUSH_MS}ms`);
    selectionLayerEl.classList.add("stats-heatmap-selection-rush");
    zoomTintEl.classList.add("stats-heatmap-zoom-tint-pass");
    // Stop the pixel mesh immediately once zoom starts so it never lingers.
    pixelMaskEl.hidden = true;

    mapViewState.focusX = Math.min(1, Math.max(0, Number(focusX) || 0.5));
    mapViewState.focusY = Math.min(1, Math.max(0, Number(focusY) || 0.5));
    const targetCoordinates = getHeatmapFocusCoordinates({
      focusX: mapViewState.focusX,
      focusY: mapViewState.focusY,
    });
    lockCoordinateTarget(targetCoordinates.latitude, targetCoordinates.longitude);
    mapZoomInputEl.value = String(
      clampHeatmapMapZoomPercent(targetZoomPercent, DEFAULT_HEATMAP_MAP_ZOOM),
    );
    render(false);
    await waitForMapZoomTransition();
    selectionAnimating = false;
    resetSelectionBox();
    if (queuedLocationFilterPoint) {
      const queuedPoint = queuedLocationFilterPoint;
      queuedLocationFilterPoint = null;
      const query = buildLocationTrafficQueryFromPoint(queuedPoint);
      if (query && typeof applyStatsQuery === "function") {
        await applyStatsQuery(query);
      }
    }
  };

  const zoomOutForLocationSelection = async () => {
    const currentZoom = clampHeatmapMapZoomPercent(
      mapZoomInputEl.value,
      DEFAULT_HEATMAP_MAP_ZOOM,
    );
    if (currentZoom <= DEFAULT_HEATMAP_MAP_ZOOM) return;

    mapViewState.focusX = 0.5;
    mapViewState.focusY = 0.5;
    mapZoomInputEl.value = String(DEFAULT_HEATMAP_MAP_ZOOM);
    render(false);
    await waitForSelectionAnimation(HEATMAP_ZOOM_SETTLE_MS);
  };

  const numberFormatter = new Intl.NumberFormat();
  const getScopeLabel = () =>
    scopeInputEl.value === HEATMAP_SCOPE_FILTERED
      ? "filtered packet results"
      : "entire capture";
  const getMetricLabel = () =>
    metricInputEl.value === HEATMAP_METRIC_BYTES ? "bytes" : "packets";

  const updateHeatmapSummaryUi = () => {
    const metric = metricInputEl.value;
    const scopeLabel = getScopeLabel();
    const filteredPacketsRaw = getFilteredPackets?.();
    const filteredPackets = Array.isArray(filteredPacketsRaw) ? filteredPacketsRaw : [];
    if (!Array.isArray(activeHeatmapData.heatmapPoints) || activeHeatmapData.heatmapPoints.length === 0) {
      if (
        scopeInputEl.value === HEATMAP_SCOPE_FILTERED
        && filteredPackets.length === 0
      ) {
        summaryEl.textContent = "No packets are currently returned by the active filter.";
      } else {
        summaryEl.textContent = "No public GeoIP coordinates are available for this selection.";
      }
      return;
    }

    if (metric === HEATMAP_METRIC_BYTES) {
      summaryEl.textContent = `${activeHeatmapData.internetHostCount} geolocated internet hosts across ${numberFormatter.format(activeHeatmapData.heatmapBytes)} bytes (${scopeLabel}).`;
      return;
    }

    summaryEl.textContent = `${activeHeatmapData.internetHostCount} geolocated internet hosts across ${numberFormatter.format(activeHeatmapData.heatmapPacketHits)} packet hits (${scopeLabel}).`;
  };

  const updateTopLocationsUi = () => {
    locationsListEl.replaceChildren();
    const points = Array.isArray(activeHeatmapData.heatmapPoints)
      ? activeHeatmapData.heatmapPoints
      : [];
    if (points.length === 0) {
      locationsSectionEl.style.display = "none";
      return;
    }

    locationsSectionEl.style.display = "block";
    const metric = getMetricLabel();
    points
      .slice()
      .sort((left, right) => right.value - left.value)
      .slice(0, 8)
      .forEach((point) => {
        const locationTagEl = documentRef.createElement("span");
        locationTagEl.className = "stats-tag";
        const metricValueLabel = `${numberFormatter.format(point.value)} ${metric}`;
        locationTagEl.textContent = `${point.label} (${metricValueLabel})`;
        locationTagEl.title = "Click once to zoom, click twice to filter traffic for this location";
        locationTagEl.addEventListener("click", async () => {
          if (lastClickedLocationPointKey === point.pointKey) {
            lastClickedLocationPointKey = null;
            if (selectionAnimating) {
              queuedLocationFilterPoint = point;
              return;
            }
            const query = buildLocationTrafficQueryFromPoint(point);
            if (query && typeof applyStatsQuery === "function") {
              await applyStatsQuery(query);
            }
            return;
          }

          lastClickedLocationPointKey = point.pointKey;
          if (selectionAnimating) return;
          await focusHeatmapLocation(point);
        });
        locationsListEl.appendChild(locationTagEl);
      });
  };

  const focusHeatmapLocation = async (locationPoint) => {
    if (!locationPoint || selectionAnimating) return false;

    const latitude = Number(locationPoint.latitude);
    const longitude = Number(locationPoint.longitude);
    if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) {
      return false;
    }

    await zoomOutForLocationSelection();
    selectedPointKey = typeof locationPoint.pointKey === "string" ? locationPoint.pointKey : null;
    const bounds = getCurrentMapBounds();
    const projected = projectGeoPoint(
      latitude,
      longitude,
      bounds.width,
      bounds.height,
      WIKIMEDIA_WORLD_MAP_PROJECTION_BOUNDS,
      getProjectionControlState(),
    );
    const centerX = bounds.left + projected.x;
    const centerY = bounds.top + projected.y;
    const selectionRect = buildLocationSelectionRect(bounds, centerX, centerY);
    const focus = getSelectionFocusFromRect(bounds, selectionRect);
    const hasCity = normalizeStatsTextValue(locationPoint.city) !== null;
    const targetZoomPercent = hasCity
      ? HEATMAP_LOCATION_CLICK_CITY_ZOOM_PERCENT
      : HEATMAP_LOCATION_CLICK_ZOOM_PERCENT;
    lockCoordinateTarget(latitude, longitude);
    await animateSelectionZoom({
      bounds,
      selectionRect,
      targetZoomPercent,
      focusX: focus.focusX,
      focusY: focus.focusY,
    });
    return true;
  };

  const buildActiveHeatmapData = () => {
    const scope = scopeInputEl.value;
    const metric = metricInputEl.value;
    if (scope === HEATMAP_SCOPE_CAPTURE && metric === HEATMAP_METRIC_PACKETS) {
      return {
        heatmapPoints: Array.isArray(stats?.heatmapPoints)
          ? stats.heatmapPoints.map((point) => ({ ...point }))
          : [],
        heatmapPacketHits: Number(stats?.heatmapPacketHits) || 0,
        heatmapBytes: 0,
        internetHostCount: Number(stats?.internetHostCount) || 0,
      };
    }

    const packetList =
      scope === HEATMAP_SCOPE_FILTERED
        ? getFilteredPackets?.()
        : getCapturePacketList(getCapturedPackets?.());
    return buildHeatmapStatsFromPacketList(packetList, metric);
  };

  const syncControlLabels = () => {
    const controlState = getControlState();
    const projectionState = getProjectionControlState();
    const zoomState = getMapZoomState();
    intensityValueEl.textContent = `${controlState.intensityPercent}%`;
    pointSizeValueEl.textContent = `${controlState.pointSizePercent}%`;
    tightnessValueEl.textContent = `${controlState.tightnessPercent}%`;
    blurValueEl.textContent = `${controlState.blurPercent}%`;
    zoomXValueEl.textContent = toCalibrationLabel(projectionState.zoomX);
    zoomYValueEl.textContent = toCalibrationLabel(projectionState.zoomY);
    offsetXValueEl.textContent = toCalibrationLabel(projectionState.offsetX);
    offsetYValueEl.textContent = toCalibrationLabel(projectionState.offsetY);
    mapZoomValueEl.textContent = `${zoomState.zoomPercent}%`;
    setCoordinateLabelFromState(zoomState);
  };

  const render = (refreshData = false) => {
    if (refreshData) {
      activeHeatmapData = buildActiveHeatmapData();
      updateHeatmapSummaryUi();
      updateTopLocationsUi();
      const locationPointKeys = new Set(
        Array.isArray(activeHeatmapData.heatmapPoints)
          ? activeHeatmapData.heatmapPoints.map((point) => point.pointKey)
          : [],
      );
      if (!locationPointKeys.has(lastClickedLocationPointKey)) {
        lastClickedLocationPointKey = null;
      }
      const selectedExists = activeHeatmapData.heatmapPoints.some(
        (point) => point.pointKey === selectedPointKey,
      );
      if (!selectedExists) {
        selectedPointKey = null;
      }
    }

    const metric = metricInputEl.value;
    const metricSuffix = metric === HEATMAP_METRIC_BYTES ? "bytes" : "packets";
    const pointsWithLabels = (activeHeatmapData.heatmapPoints || []).map((point) => ({
      ...point,
      valueLabel: `${numberFormatter.format(point.value)} ${metricSuffix}`,
    }));

    const previousZoomPercent = clampHeatmapMapZoomPercent(
      lastRenderedZoomPercent,
      DEFAULT_HEATMAP_MAP_ZOOM,
    );
    projectionCalibration = getProjectionControlState();
    mapViewState = getMapZoomState();
    const nextZoomPercent = clampHeatmapMapZoomPercent(
      mapViewState.zoomPercent,
      DEFAULT_HEATMAP_MAP_ZOOM,
    );
    const zoomChanged = previousZoomPercent !== nextZoomPercent;
    let zoomTransitionToken = 0;
    if (zoomChanged) {
      zoomTransitionToken = beginMapZoomVisualTransition();
    }
    syncControlLabels();
    renderStatsHeatmap(
      mapEl,
      basemapFrameEl,
      gridLayerEl,
      heatmapLayerEl,
      pointLayerEl,
      pointsWithLabels,
      projectionCalibration,
      getControlState(),
      mapViewState,
      {
        preferLowResBasemap: mapZoomVisualTransitionActive,
      },
    );
    highlightHeatmapPoint(pointLayerEl, selectedPointKey);
    if (lockedCoordinate) {
      updateLockedAimPosition();
    } else if (hoverAimState) {
      setAimPosition(hoverAimState.x, hoverAimState.y, true);
    }
    lastRenderedZoomPercent = nextZoomPercent;

    if (zoomChanged) {
      void waitForMapZoomTransition().then(() => {
        endMapZoomVisualTransition(zoomTransitionToken);
      });
    }
  };

  intensityInputEl.addEventListener("input", () => render(false));
  pointSizeInputEl.addEventListener("input", () => render(false));
  tightnessInputEl.addEventListener("input", () => render(false));
  blurInputEl.addEventListener("input", () => render(false));
  scopeInputEl.addEventListener("change", () => render(true));
  metricInputEl.addEventListener("change", () => render(true));
  mapZoomInputEl.addEventListener("input", () => render(false));
  mapZoomControlEl.addEventListener("mousedown", (event) => {
    mapZoomInteractionActive = true;
    event.stopPropagation();
  });
  mapZoomControlEl.addEventListener("mouseup", () => {
    mapZoomInteractionActive = false;
  });
  mapZoomControlEl.addEventListener("mouseleave", () => {
    mapZoomInteractionActive = false;
  });
  mapZoomInputEl.addEventListener("blur", () => {
    mapZoomInteractionActive = false;
  });
  zoomXInputEl.addEventListener("input", () => {
    if (calibrationLocked) return;
    render(false);
    scheduleProjectionCalibrationSave();
  });
  zoomYInputEl.addEventListener("input", () => {
    if (calibrationLocked) return;
    render(false);
    scheduleProjectionCalibrationSave();
  });
  offsetXInputEl.addEventListener("input", () => {
    if (calibrationLocked) return;
    render(false);
    scheduleProjectionCalibrationSave();
  });
  offsetYInputEl.addEventListener("input", () => {
    if (calibrationLocked) return;
    render(false);
    scheduleProjectionCalibrationSave();
  });
  calibrationLockInputEl.addEventListener("change", () => {
    calibrationLocked = Boolean(calibrationLockInputEl.checked);
    updateCalibrationControlEnabledState();
    scheduleProjectionCalibrationSave();
  });
  resetControlsBtn.addEventListener("click", () => {
    intensityInputEl.value = String(DEFAULT_HEATMAP_INTENSITY);
    pointSizeInputEl.value = String(DEFAULT_HEATMAP_POINT_SIZE);
    tightnessInputEl.value = String(DEFAULT_HEATMAP_TIGHTNESS);
    blurInputEl.value = String(DEFAULT_HEATMAP_BLUR);
    projectionCalibration = {
      zoomX: WIKIMEDIA_WORLD_MAP_PROJECTION_ZOOM_X,
      zoomY: WIKIMEDIA_WORLD_MAP_PROJECTION_ZOOM_Y,
      offsetX: WIKIMEDIA_WORLD_MAP_PROJECTION_OFFSET_X,
      offsetY: WIKIMEDIA_WORLD_MAP_PROJECTION_OFFSET_Y,
    };
    mapViewState = {
      zoomPercent: DEFAULT_HEATMAP_MAP_ZOOM,
      focusX: 0.5,
      focusY: 0.5,
    };
    mapZoomInputEl.value = String(DEFAULT_HEATMAP_MAP_ZOOM);
    lastStatsMapProjectionCalibration = projectionCalibration;
    applyProjectionControlsFromCalibration(projectionCalibration);
    scheduleProjectionCalibrationSave();
    render(true);
  });

  const onMapMouseDown = (event) => {
    if (selectionAnimating) return;
    if (mapZoomInteractionActive) return;
    if (isMapZoomInteractionTarget(event.target)) return;
    if (event.button !== 0) return;
    const bounds = getCurrentMapBounds();
    const point = getMapEventPoint(event);
    const withinBounds =
      point.x >= bounds.left
      && point.x <= bounds.left + bounds.width
      && point.y >= bounds.top
      && point.y <= bounds.top + bounds.height;
    if (!withinBounds) return;

    lockedCoordinate = null;
    clearAimState();

    dragSelectionState = {
      bounds,
      startX: point.x,
      startY: point.y,
      currentX: point.x,
      currentY: point.y,
    };
    updateSelectionBox(point.x, point.y, point.x, point.y);
    mapEl.classList.add("stats-heatmap-selecting");
    event.preventDefault();
  };

  const onMapMouseMove = (event) => {
    if (selectionAnimating) return;
    if (!dragSelectionState) return;
    const point = getMapEventPoint(event);
    const bounds = dragSelectionState.bounds;
    const withinBounds =
      point.x >= bounds.left
      && point.x <= bounds.left + bounds.width
      && point.y >= bounds.top
      && point.y <= bounds.top + bounds.height;
    if (!withinBounds) return;
    dragSelectionState.currentX = point.x;
    dragSelectionState.currentY = point.y;
    updateSelectionBox(
      dragSelectionState.startX,
      dragSelectionState.startY,
      dragSelectionState.currentX,
      dragSelectionState.currentY,
    );
  };

  const onMapMouseUp = async (event) => {
    if (!dragSelectionState) return;

    const releasePoint = getMapEventPoint(event);
    const bounds = dragSelectionState.bounds;
    const withinBounds =
      releasePoint.x >= bounds.left
      && releasePoint.x <= bounds.left + bounds.width
      && releasePoint.y >= bounds.top
      && releasePoint.y <= bounds.top + bounds.height;
    if (!withinBounds) {
      resetSelectionBox();
      return;
    }

    const selectionWidth = Math.abs(dragSelectionState.currentX - dragSelectionState.startX);
    const selectionHeight = Math.abs(dragSelectionState.currentY - dragSelectionState.startY);
    if (
      selectionWidth < HEATMAP_SELECTION_MIN_PIXELS
      || selectionHeight < HEATMAP_SELECTION_MIN_PIXELS
    ) {
      resetSelectionBox();
      return;
    }

    const zoomConfig = applySelectionZoom();
    if (!zoomConfig) {
      resetSelectionBox();
      return;
    }
    await animateSelectionZoom({
      bounds: dragSelectionState.bounds,
      selectionRect: zoomConfig.selectionRect,
      targetZoomPercent: zoomConfig.targetZoomPercent,
      focusX: zoomConfig.focusX,
      focusY: zoomConfig.focusY,
    });
  };

  const onMapDoubleClick = (event) => {
    if (selectionAnimating) return;
    resetSelectionBox();
    mapViewState.focusX = 0.5;
    mapViewState.focusY = 0.5;
    lockedCoordinate = null;
    clearAimState();
    mapZoomInputEl.value = String(DEFAULT_HEATMAP_MAP_ZOOM);
    render(false);
    event.preventDefault();
  };

  const onMapHoverMove = (event) => {
    if (selectionAnimating || dragSelectionState || lockedCoordinate) return;
    if (isMapZoomInteractionTarget(event.target)) return;
    const bounds = getCurrentMapBounds();
    const point = getMapEventPoint(event);
    const withinBounds =
      point.x >= bounds.left
      && point.x <= bounds.left + bounds.width
      && point.y >= bounds.top
      && point.y <= bounds.top + bounds.height;
    if (!withinBounds) {
      hoverAimState = null;
      setAimPosition(0, 0, false);
      setCoordinateLabelFromState(getMapZoomState());
      return;
    }

    const geo = convertViewportPointToGeoCoordinates(
      bounds,
      point,
      getMapZoomState(),
      getProjectionControlState(),
    );
    if (!geo) return;
    hoverAimState = {
      x: point.x,
      y: point.y,
      latitude: geo.latitude,
      longitude: geo.longitude,
    };
    setAimPosition(point.x, point.y, true);
    setCoordinateLabelFromState(getMapZoomState());
  };

  const onMapMouseLeave = () => {
    if (lockedCoordinate) return;
    hoverAimState = null;
    setAimPosition(0, 0, false);
    setCoordinateLabelFromState(getMapZoomState());
  };

  mapEl.addEventListener("mousedown", onMapMouseDown);
  mapEl.addEventListener("mousemove", onMapHoverMove);
  mapEl.addEventListener("mouseleave", onMapMouseLeave);
  mapEl.addEventListener("dblclick", onMapDoubleClick);
  window.addEventListener("mousemove", onMapMouseMove);
  window.addEventListener("mouseup", () => {
    mapZoomInteractionActive = false;
  });
  window.addEventListener("mouseup", onMapMouseUp);

  toggleControlsBtn.addEventListener("click", () => {
    controlsCollapsed = !controlsCollapsed;
    syncControlsCollapsedUi();
    render(false);
  });

  syncControlsCollapsedUi();
  calibrationLockInputEl.checked = calibrationLocked;
  updateCalibrationControlEnabledState();
  syncControlLabels();
  render(true);

  return {
    section,
    render,
    focusLocation: async ({ latitude, longitude }) => {
      const lat = Number(latitude);
      const lon = Number(longitude);
      if (!Number.isFinite(lat) || !Number.isFinite(lon)) return false;

      const candidatePoint = Array.isArray(activeHeatmapData.heatmapPoints)
        ? activeHeatmapData.heatmapPoints.find(
          (point) => Number(point.latitude) === lat && Number(point.longitude) === lon,
        )
        : null;

      return focusHeatmapLocation(
        candidatePoint || {
          latitude: lat,
          longitude: lon,
          pointKey: null,
        },
      );
    },
    dispose: () => {
      if (persistCalibrationTimeoutId) {
        window.clearTimeout(persistCalibrationTimeoutId);
      }
      mapEl.removeEventListener("mousedown", onMapMouseDown);
      mapEl.removeEventListener("mousemove", onMapHoverMove);
      mapEl.removeEventListener("mouseleave", onMapMouseLeave);
      mapEl.removeEventListener("dblclick", onMapDoubleClick);
      window.removeEventListener("mousemove", onMapMouseMove);
      window.removeEventListener("mouseup", onMapMouseUp);
    },
  };
}

// Collects packet decoded protocol names.
function collectPacketDecodedProtocolNames(packetInfo) {
  const decodedNames = new Set();

  const packetDecoded =
    packetInfo?.["packet.decoded_protocols"] || packetInfo?.["Decoded Protocols"];
  if (Array.isArray(packetDecoded)) {
    packetDecoded.forEach((decodedProtocol) => {
      const name = normalizeStatsTextValue(decodedProtocol);
      if (name) decodedNames.add(name);
    });
  }

  const linkControlDecoded =
    packetInfo?.["Link Control"]?.["Detected Protocols"] ||
    packetInfo?.["Link Control"]?.["wan.detected"];
  if (Array.isArray(linkControlDecoded)) {
    linkControlDecoded.forEach((decodedProtocol) => {
      const name = normalizeStatsTextValue(decodedProtocol);
      if (name) decodedNames.add(name);
    });
  }

  const sectionNames = ["TCP", "UDP", "SCTP", "ICMP", "IGMP", "LINK", "IP"];
  sectionNames.forEach((sectionName) => {
    const section = packetInfo?.[sectionName];
    if (!section || typeof section !== "object") return;
    Object.entries(section).forEach(([fieldName, fieldValue]) => {
      if (isProtocolLikeFieldName(fieldName, fieldValue)) {
        const name = normalizeStatsTextValue(fieldName);
        if (name) decodedNames.add(name);
      }
    });
  });

  return [...decodedNames];
}

// Normalizes stats text value.
function normalizeStatsTextValue(value, options = {}) {
  if (value === null || value === undefined) return null;

  const { stripNonPrintable = false } = options;
  let normalized = typeof value === "string" ? value : String(value);

  if (stripNonPrintable) {
    normalized = normalized.replace(/[\x00-\x1F\x7F]/g, "");
  }

  normalized = normalized.trim();
  return normalized ? normalized : null;
}

// Normalizes stats port value.
function normalizeStatsPortValue(value) {
  if (value === null || value === undefined) return null;
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  const normalizedText = normalizeStatsTextValue(value);
  if (!normalizedText || !/^\d+$/.test(normalizedText)) return null;
  return Number(normalizedText);
}

// Parses stats packet timestamp ms.
function parseStatsPacketTimestampMs(packet) {
  const packetTimestamp = packet?.["packet.info"]?.["packet.timestamp"] ?? packet?.["packet.info"]?.["Packet Timestamp"];
  if (typeof packetTimestamp !== "string" || !packetTimestamp.trim()) {
    return null;
  }
  const parsedTimestamp = Date.parse(packetTimestamp);
  return Number.isFinite(parsedTimestamp) ? parsedTimestamp : null;
}

// Parses stats packet processed number.
function parseStatsPacketProcessedNumber(packet) {
  const processedRaw = Number(packet?.["packet.info"]?.["packet.processed"] ?? packet?.["packet.info"]?.["Packet Processed"]);
  return Number.isFinite(processedRaw) ? processedRaw : null;
}

// Parses stats packet index number.
function parseStatsPacketIndexNumber(packet) {
  const packetIndexRaw = Number(packet?.["packet.info"]?.["index"] ?? packet?.["packet.info"]?.["Index"]);
  return Number.isFinite(packetIndexRaw) ? packetIndexRaw : null;
}

// Handles compare stats packets chronologically.
function compareStatsPacketsChronologically(
  leftPacket,
  rightPacket,
  leftFallbackOrder = 0,
  rightFallbackOrder = 0,
) {
  const leftTimestamp = parseStatsPacketTimestampMs(leftPacket);
  const rightTimestamp = parseStatsPacketTimestampMs(rightPacket);
  if (leftTimestamp !== null && rightTimestamp !== null && leftTimestamp !== rightTimestamp) {
    return leftTimestamp - rightTimestamp;
  }
  if (leftTimestamp !== null && rightTimestamp === null) return -1;
  if (leftTimestamp === null && rightTimestamp !== null) return 1;

  const leftProcessed = parseStatsPacketProcessedNumber(leftPacket);
  const rightProcessed = parseStatsPacketProcessedNumber(rightPacket);
  if (leftProcessed !== null && rightProcessed !== null && leftProcessed !== rightProcessed) {
    return leftProcessed - rightProcessed;
  }
  if (leftProcessed !== null && rightProcessed === null) return -1;
  if (leftProcessed === null && rightProcessed !== null) return 1;

  const leftIndex = parseStatsPacketIndexNumber(leftPacket);
  const rightIndex = parseStatsPacketIndexNumber(rightPacket);
  if (leftIndex !== null && rightIndex !== null && leftIndex !== rightIndex) {
    return leftIndex - rightIndex;
  }
  if (leftIndex !== null && rightIndex === null) return -1;
  if (leftIndex === null && rightIndex !== null) return 1;

  return leftFallbackOrder - rightFallbackOrder;
}

// Parses stats tcp sequence number.
function parseStatsTcpSequenceNumber(transportData) {
  const sequenceCandidates = [
    transportData?.["TCP Sequence Number"],
    transportData?.["tcp.seq"],
    transportData?.["Sequence Number"],
    transportData?.["Sequence"],
  ];
  for (const candidate of sequenceCandidates) {
    const parsed = Number(candidate);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

// Returns stats tcp segment length.
function getStatsTcpSegmentLength(packetInfo, transportData) {
  const payloadLenRaw = Number(
    packetInfo?.["raw.data"]?.["payload.len"] ??
    packetInfo?.["Raw data"]?.["payload.len"] ??
    packetInfo?.["Raw data"]?.["Payload Length"]
  );
  const payloadLen = Number.isFinite(payloadLenRaw) && payloadLenRaw > 0
    ? payloadLenRaw
    : 0;

  const flagsText = String(transportData?.["TCP Flag Data"]?.["Flags"] || "").toUpperCase();
  const controlByteLength =
    (flagsText.includes("SYN") ? 1 : 0) + (flagsText.includes("FIN") ? 1 : 0);
  return payloadLen + controlByteLength;
}

// Handles merge stats sequence range.
function mergeStatsSequenceRange(ranges, start, end) {
  if (!Array.isArray(ranges) || !Number.isFinite(start) || !Number.isFinite(end) || end <= start) {
    return;
  }

  ranges.push({ start, end });
  ranges.sort((left, right) => left.start - right.start);

  const merged = [];
  for (const currentRange of ranges) {
    if (!merged.length) {
      merged.push({ ...currentRange });
      continue;
    }
    const lastRange = merged[merged.length - 1];
    if (currentRange.start <= lastRange.end) {
      lastRange.end = Math.max(lastRange.end, currentRange.end);
      continue;
    }
    merged.push({ ...currentRange });
  }

  ranges.length = 0;
  ranges.push(...merged);
}

// Returns stats sequence range overlap length.
function getStatsSequenceRangeOverlapLength(ranges, start, end) {
  if (!Array.isArray(ranges) || end <= start) return 0;
  let overlapLength = 0;
  for (const range of ranges) {
    if (range.end <= start) continue;
    if (range.start >= end) break;
    const overlapStart = Math.max(start, range.start);
    const overlapEnd = Math.min(end, range.end);
    if (overlapEnd > overlapStart) {
      overlapLength += overlapEnd - overlapStart;
    }
  }
  return overlapLength;
}

// Computes tcp stream anomaly counts.
function computeTcpStreamAnomalyCounts(streamPacketsByKey) {
  let retransmissionCount = 0;
  let outOfOrderCount = 0;

  streamPacketsByKey.forEach((streamPackets) => {
    if (!Array.isArray(streamPackets) || streamPackets.length === 0) return;

    const sortedStreamPackets = streamPackets
      .map((packet, originalOrder) => ({ packet, originalOrder }))
      .sort((left, right) =>
        compareStatsPacketsChronologically(
          left.packet,
          right.packet,
          left.originalOrder,
          right.originalOrder,
        ),
      )
      .map((entry) => entry.packet);

    const streamStateByDirection = new Map();
    sortedStreamPackets.forEach((packet) => {
      const packetInfo = packet?.["packet.info"] || {};
      const protocol = String(packetInfo["packet.proto"] ?? packetInfo["Protocol"] ?? "").toUpperCase();
      if (protocol !== "TCP") return;

      const transportData = packetInfo["TCP"] || {};
      const sourceIp = (packetInfo?.["IP"]?.["ip.src.addr"] ?? packetInfo?.["IP"]?.["Source IP"]) || "";
      const destinationIp = (packetInfo?.["IP"]?.["ip.dst.addr"] ?? packetInfo?.["IP"]?.["Destination IP"]) || "";
      const sourcePort = transportData?.["tcp.src.port"] ?? transportData?.["Source port"] ?? "";
      const destinationPort = transportData?.["tcp.dst.port"] ?? transportData?.["Destination port"] ?? "";
      const directionKey = `${sourceIp}:${sourcePort}>${destinationIp}:${destinationPort}`;
      const sequenceNumber = parseStatsTcpSequenceNumber(transportData);
      const segmentLength = getStatsTcpSegmentLength(packetInfo, transportData);

      const state = streamStateByDirection.get(directionKey) || {
        seenRanges: [],
        maxStartObserved: null,
      };

      if (sequenceNumber === null || segmentLength <= 0) {
        streamStateByDirection.set(directionKey, state);
        return;
      }

      const sequenceEnd = sequenceNumber + segmentLength;
      const overlapLength = getStatsSequenceRangeOverlapLength(
        state.seenRanges,
        sequenceNumber,
        sequenceEnd,
      );
      const isRetransmission = overlapLength > 0;
      const isOutOfOrder =
        Number.isFinite(state.maxStartObserved) && sequenceNumber < state.maxStartObserved;

      if (isRetransmission) retransmissionCount += 1;
      if (isOutOfOrder) outOfOrderCount += 1;

      mergeStatsSequenceRange(state.seenRanges, sequenceNumber, sequenceEnd);
      state.maxStartObserved = Number.isFinite(state.maxStartObserved)
        ? Math.max(state.maxStartObserved, sequenceNumber)
        : sequenceNumber;
      streamStateByDirection.set(directionKey, state);
    });
  });

  return {
    retransmissionCount,
    outOfOrderCount,
  };
}

// Builds capture stats.
function buildCaptureStats(capturedPackets, bookmarkCount = 0) {
  const protocols = new Set();
  const networkProtocols = new Set();
  const linkProtocols = new Set();
  const transportProtocols = new Set();
  const decodedProtocols = new Set();
  const arpOperations = new Set();
  const igmpMessageTypes = new Set();
  const hosts = new Set();
  const ports = new Set();
  const macVendors = new Set();
  const mimeTypes = new Set();
  const locations = new Map();
  const heatmapPointsByCoordinate = new Map();
  const internetHosts = new Set();
  const hostnames = new Set();
  const dataTypes = new Set();
  const streams = new Map();
  const tcpStreams = new Map();
  let encryptedCount = 0;
  let unencryptedCount = 0;
  let undecodableCount = 0;
  let totalPackets = 0;
  if (!capturedPackets || !capturedPackets["host"]) return null;

  const getStreamKey = (packetInfo) => {
    const transportName = packetInfo?.["packet.proto"] ?? packetInfo?.["Protocol"] ?? "Unknown";
    const transportData = packetInfo?.[transportName] || {};
    const sourceIp = packetInfo?.["IP"]?.["ip.src.addr"] ?? packetInfo?.["IP"]?.["Source IP"] ?? "";
    const destinationIp = packetInfo?.["IP"]?.["ip.dst.addr"] ?? packetInfo?.["IP"]?.["Destination IP"] ?? "";
    const sourcePort =
      transportData?.["tcp.src.port"] ??
      transportData?.["udp.src.port"] ??
      transportData?.["sctp.src.port"] ??
      transportData?.["Source port"] ??
      "";
    const destinationPort =
      transportData?.["tcp.dst.port"] ??
      transportData?.["udp.dst.port"] ??
      transportData?.["sctp.dst.port"] ??
      transportData?.["Destination port"] ??
      "";

    const endpointA = `${sourceIp}:${sourcePort}`;
    const endpointB = `${destinationIp}:${destinationPort}`;
    const [firstEndpoint, secondEndpoint] = [endpointA, endpointB].sort();
    return `${transportName}|${firstEndpoint}|${secondEndpoint}`;
  };

  for (const host of Object.keys(capturedPackets["host"])) {
    const normalizedHostKey = normalizeStatsTextValue(host);
    if (normalizedHostKey) hosts.add(normalizedHostKey);
    const packets = capturedPackets["host"][host];
    if (!Array.isArray(packets)) continue;

    for (const pkt of packets) {
      totalPackets++;
      const pi = pkt?.["packet.info"];
      const ei = pkt?.["extra.info"] || {};
      if (!pi) continue;

      const streamKey = getStreamKey(pi);
      if (!streams.has(streamKey)) {
        streams.set(streamKey, { count: 0 });
      }
      streams.get(streamKey).count++;

      const protocolUpper = String(pi?.["packet.proto"] ?? pi?.["Protocol"] ?? "").toUpperCase();
      if (protocolUpper === "TCP") {
        if (!tcpStreams.has(streamKey)) {
          tcpStreams.set(streamKey, []);
        }
        tcpStreams.get(streamKey).push(pkt);
      }

      const tp = normalizeStatsTextValue(pi["packet.proto"] ?? pi["Protocol"]);
      if (tp) transportProtocols.add(tp);
      if (tp && tp.toLowerCase() === "undecodable") {
        undecodableCount++;
      }
      const packetProto = normalizeStatsTextValue(pi?.["packet.proto"] || tp);
      if (packetProto) networkProtocols.add(packetProto);

      const linkData = pi?.["Link Control"];
      if (linkData) {
        const primaryLinkProtocol = normalizeStatsTextValue(
          linkData?.["Primary WAN Protocol"],
        );
        if (primaryLinkProtocol) linkProtocols.add(primaryLinkProtocol);

        const detectedLinkProtocols = linkData?.["Detected Protocols"];
        if (Array.isArray(detectedLinkProtocols)) {
          detectedLinkProtocols.forEach((linkProtocol) => {
            const normalizedLinkProtocol = normalizeStatsTextValue(linkProtocol);
            if (normalizedLinkProtocol) linkProtocols.add(normalizedLinkProtocol);
          });
        }
      }

      const inferredDecodedProtocols = collectPacketDecodedProtocolNames(pi);
      inferredDecodedProtocols.forEach((decodedProtocol) => {
        const normalizedDecodedProtocol = normalizeStatsTextValue(decodedProtocol);
        if (normalizedDecodedProtocol) decodedProtocols.add(normalizedDecodedProtocol);
      });

      if (tp === "ARP" || tp === "RARP") {
        const arpData = pi?.[tp] || {};
        const arpOp = normalizeStatsTextValue(arpData["Operation"]);
        if (arpOp) arpOperations.add(arpOp);
      }

      if (tp === "IGMP") {
        const igmpData = pi?.["IGMP"] || {};
        const igmpType = normalizeStatsTextValue(igmpData["Type"]);
        if (igmpType) igmpMessageTypes.add(igmpType);
      }

      const srcIp = normalizeStatsTextValue(pi?.["IP"]?.["ip.src.addr"] ?? pi?.["IP"]?.["Source IP"]);
      const dstIp = normalizeStatsTextValue(pi?.["IP"]?.["ip.dst.addr"] ?? pi?.["IP"]?.["Destination IP"]);
      if (srcIp) hosts.add(srcIp);
      if (dstIp) hosts.add(dstIp);

      const ef = pi?.["Ethernet Frame"];
      if (ef) {
        const srcVendor = normalizeStatsTextValue(ef["ether.src.mac.vendor"] ?? ef["MAC Source Vendor"]);
        const dstVendor = normalizeStatsTextValue(ef["MAC Destination Vendor"]);
        if (srcVendor) macVendors.add(srcVendor);
        if (dstVendor) macVendors.add(dstVendor);
      }

      const netData = ei?.["Traits"]?.["Network Data"];
      if (netData) {
        const protoName = normalizeStatsTextValue(
          netData["Port Protocol"] ?? netData["Port Protcol"],
        );
        if (protoName && protoName !== "Unknown") protocols.add(protoName);

        const tpData = tp ? pi[tp] : null;
        if (tpData) {
          const srcPort = normalizeStatsPortValue(
            tpData["tcp.src.port"] ?? tpData["udp.src.port"] ?? tpData["sctp.src.port"] ?? tpData["Source port"],
          );
          const dstPort = normalizeStatsPortValue(
            tpData["tcp.dst.port"] ?? tpData["udp.dst.port"] ?? tpData["sctp.dst.port"] ?? tpData["Destination port"],
          );
          if (srcPort !== null) ports.add(srcPort);
          if (dstPort !== null) ports.add(dstPort);
        }

        const hn = netData?.["Hostnames"]?.["Hostnames"];
        if (Array.isArray(hn)) {
          hn.forEach((h) => {
            const normalizedHostname = normalizeStatsTextValue(h);
            if (normalizedHostname) hostnames.add(normalizedHostname);
          });
        }

        for (const [dotSide, legacySide] of [["ip.src", "Source IP"], ["ip.dst", "Destination IP"]]) {
          const loc = netData?.[dotSide]?.["Location"] ?? netData?.[legacySide]?.["Location"];
          const city = normalizeStatsTextValue(loc?.["City"]);
          const country = normalizeStatsTextValue(loc?.["Country"]);
          if (city && country) {
            const key = `${city}, ${country}`;
            locations.set(key, (locations.get(key) || 0) + 1);
          }

          const ipAddress =
            dotSide === "ip.src"
              ? pi?.["IP"]?.["ip.src.addr"] ?? pi?.["IP"]?.["Source IP"]
              : pi?.["IP"]?.["ip.dst.addr"] ?? pi?.["IP"]?.["Destination IP"];
          const mappedPoint = collectInternetLocationPoint(loc, city || country, ipAddress);
          if (mappedPoint) {
            const coordinateKey = `${mappedPoint.latitude.toFixed(4)},${mappedPoint.longitude.toFixed(4)}`;
            const existingPoint = heatmapPointsByCoordinate.get(coordinateKey);
            if (existingPoint) {
              existingPoint.value += 1;
              if (mappedPoint.ipAddress) {
                existingPoint.ipAddresses.add(mappedPoint.ipAddress);
              }
              if (!existingPoint.city && mappedPoint.city) {
                existingPoint.city = mappedPoint.city;
              }
              if (!existingPoint.country && mappedPoint.country) {
                existingPoint.country = mappedPoint.country;
              }
            } else {
              const ipAddresses = new Set();
              if (mappedPoint.ipAddress) {
                ipAddresses.add(mappedPoint.ipAddress);
              }
              heatmapPointsByCoordinate.set(coordinateKey, {
                pointKey: coordinateKey,
                latitude: mappedPoint.latitude,
                longitude: mappedPoint.longitude,
                label: mappedPoint.label,
                city: mappedPoint.city,
                country: mappedPoint.country,
                value: 1,
                ipAddresses,
              });
            }
            if (mappedPoint.ipAddress) {
              internetHosts.add(mappedPoint.ipAddress);
            }
          }
        }
      }

      const mimeType = normalizeStatsTextValue(ei?.["MIME Type"]);
      if (mimeType) mimeTypes.add(mimeType);

      const dt = ei?.["Data Types"];
      if (Array.isArray(dt)) {
        const uniqueDataTypes = new Set();
        dt.forEach((d) => {
          const normalizedDataType = normalizeStatsTextValue(d, {
            stripNonPrintable: true,
          });
          //  only add up to 40 unique data types to avoid overwhelming the stats panel
          if (normalizedDataType && uniqueDataTypes.size < 40) {
            uniqueDataTypes.add(normalizedDataType);
          }
        });
        uniqueDataTypes.forEach((normalizedDataType) => {

          dataTypes.add(normalizedDataType);
        }
        );
      }

      const encData = ei?.["Traits"]?.["Server Info"]?.["Encryption Data"];
      if (!encData || encData === "N/A") {
        unencryptedCount++;
      } else {
        encryptedCount++;
      }
    }
  }

  const streamStats = Array.from(streams.values()).map((s) => s.count);
  const maxStreamLength =
    streamStats.length > 1 ? Math.max(...streamStats) : 0;
  const minStreamLength =
    streamStats.length > 1 ? Math.min(...streamStats) : 0;
  const avgStreamLength =
    streamStats.length > 1
      ? (streamStats.reduce((a, b) => a + b, 0) / streamStats.length).toFixed(2)
      : 0;
  const tcpStreamAnomalyCounts = computeTcpStreamAnomalyCounts(tcpStreams);
  const uniqueCredentials = getUniqueCredentialList();

  return {
    protocols: [...protocols].sort(),
    networkProtocols: [...networkProtocols].sort(),
    linkProtocols: [...linkProtocols].sort(),
    transportProtocols: [...transportProtocols].sort(),
    decodedProtocols: [...decodedProtocols].sort(),
    arpOperations: [...arpOperations].sort(),
    igmpMessageTypes: [...igmpMessageTypes].sort(),
    hosts: [...hosts].sort(),
    ports: [...ports].sort((a, b) => a - b),
    macVendors: [...macVendors].filter((v) => v !== "N/A").sort(),
    mimeTypes: [...mimeTypes].sort(),
    locations: [...locations.entries()].sort((a, b) => b[1] - a[1]),
    heatmapPoints: [...heatmapPointsByCoordinate.values()].sort((a, b) => b.value - a.value),
    heatmapPacketHits: [...heatmapPointsByCoordinate.values()].reduce(
      (total, point) => total + point.value,
      0,
    ),
    internetHostCount: internetHosts.size,
    hostnames: [...hostnames].sort(),
    dataTypes: [...dataTypes].sort(),
    topTalkers: getTopTalkers(capturedPackets, 5),
    encryptedCount,
    unencryptedCount,
    undecodableCount,
    totalPackets,
    totalStreams: streams.size,
    maxStreamLength,
    minStreamLength,
    avgStreamLength,
    creds: getCredentialsFromKeystore(),
    uniqueCredentialCount: uniqueCredentials.length,
    uniqueCredentials,
    totalTraffic: totalTrafficBytes(capturedPackets),
    retransmissionCount: tcpStreamAnomalyCounts.retransmissionCount,
    outOfOrderCount: tcpStreamAnomalyCounts.outOfOrderCount,
    bookmarkCount,
  };
}

// Handles make stats section.
function makeStatsSection({
  documentRef,
  title,
  items,
  queryBuilder,
  onQuery,
  onItemClick,
  itemTitle,
}) {
  if (!items || items.length === 0) return null;
  const normalizedItems = Array.from(
    new Set(
      items.filter((item) => {
        if (item === null || item === undefined) return false;
        if (typeof item !== "string") return true;
        return normalizeStatsTextValue(item) !== null;
      }),
    ),
  );
  if (normalizedItems.length === 0) return null;

  const section = documentRef.createElement("div");
  section.className = "stats-section";

  const heading = documentRef.createElement("div");
  heading.className = "stats-section-title";
  heading.textContent = title;
  section.appendChild(heading);

  const tagList = documentRef.createElement("div");
  tagList.className = "stats-tag-list";

  normalizedItems.forEach((item) => {
    const tag = documentRef.createElement("span");
    tag.className = "stats-tag";
    tag.textContent = item;
    const isFilterTag = typeof queryBuilder === "function";
    const hasCustomClick = typeof onItemClick === "function";
    if (isFilterTag) {
      tag.title = "Click to filter packets by this value";
    } else if (typeof itemTitle === "function") {
      const resolvedTitle = itemTitle(item);
      if (resolvedTitle) tag.title = resolvedTitle;
    } else if (typeof itemTitle === "string" && itemTitle.trim()) {
      tag.title = itemTitle;
    }

    if (queryBuilder) {
      tag.addEventListener("click", () => {
        const query = queryBuilder(item);
        if (query && typeof onQuery === "function") {
          onQuery(query);
        }
      });
    } else if (hasCustomClick) {
      tag.addEventListener("click", () => {
        onItemClick(item);
      });
    }
    tagList.appendChild(tag);
  });

  section.appendChild(tagList);
  return section;
}

// Handles total traffic bytes.
function totalTrafficBytes(capturedPackets) {
  let totalBytes = 0;
  for (const host of Object.keys(capturedPackets["host"] || {})) {
    const packets = capturedPackets["host"][host];
    if (!Array.isArray(packets)) continue;

    for (const pkt of packets) {
      const pi = pkt?.["packet.info"];
      if (!pi) continue;

      const rawData = pi?.["raw.data"] ?? pi?.["Raw data"];
      const payloadLength = Number(rawData?.["payload.len"] ?? rawData?.["Payload Length"]);
      if (Number.isFinite(payloadLength) && payloadLength > 0) {
        totalBytes += payloadLength;
      }
    }
  }
  return totalBytes;
}



// Creates stats panel.
function createStatsPanel(options) {
  const {
    keystorePanel,
    getKeystorePanel,
    documentRef,
    statusUpdate,
    writeLogEntry,
    getCurrentSettings,
    setActiveMainTab,
    mainTabStats,
    getJsonCapture,
    getCapturedPackets,
    filterInputEl,
    syncFilterHighlight,
    runFilterQuery,
    getFilteredPackets,
    syncTargetHostFromPackets,
    setPacketsForHost,
    getBookmarkCount,
    listCarvableFilesForStats,
    openCarvedFileInConv,
  } = options;
  let disposeHeatmapResize = null;
  const resolveKeystorePanel = () => {
    if (typeof getKeystorePanel === "function") return getKeystorePanel();
    return keystorePanel;
  };

  function createCarvableFilesSection() {
    const section = documentRef.createElement("div");
    section.className = "stats-section";

    const heading = documentRef.createElement("div");
    heading.className = "stats-section-title";
    heading.textContent = "Carvable Files";
    section.appendChild(heading);

    const noteEl = documentRef.createElement("div");
    noteEl.className = "stats-inline-note";
    noteEl.textContent = "Scanning carve candidates from HTTP/FTP/NFS/SMB streams...";
    section.appendChild(noteEl);

    const listEl = documentRef.createElement("div");
    listEl.className = "stats-tag-list";
    section.appendChild(listEl);

    const renderNoFiles = (messageText) => {
      listEl.replaceChildren();
      noteEl.textContent = messageText;
    };

    const renderFiles = (items) => {
      listEl.replaceChildren();
      if (!Array.isArray(items) || items.length === 0) {
        renderNoFiles("No carvable files were detected in HTTP/FTP/NFS/SMB streams.");
        return;
      }

      noteEl.textContent = "Click a carved file candidate to load it into Conv.";
      items.forEach((item) => {
        const tag = documentRef.createElement("span");
        tag.className = "stats-tag";
        tag.textContent = String(item?.label || "Unknown carved file");
        tag.title = `Load into Conv (${String(item?.sourceDetail || "stream context")})`;
        tag.addEventListener("click", async () => {
          if (typeof openCarvedFileInConv !== "function") return;
          try {
            await openCarvedFileInConv(item);
          } catch (error) {
            const message = error?.message || String(error || "unknown");
            statusUpdate(`Status: Failed to load carved file into Conv - ${message}`);
            writeLogEntry(`[${threadName}] Failed to load carved file candidate: ${message}`);
          }
        });
        listEl.appendChild(tag);
      });
    };

    const loadFiles = async () => {
      if (typeof listCarvableFilesForStats !== "function") {
        renderNoFiles("Carvable file listing is unavailable in this build.");
        return;
      }
      try {
        const items = await listCarvableFilesForStats();
        renderFiles(items);
      } catch (error) {
        const message = error?.message || String(error || "unknown");
        renderNoFiles("Failed to scan carve candidates. Check activity log for details.");
        writeLogEntry(`[${threadName}] Failed to collect carvable files: ${message}`);
      }
    };

    return {
      section,
      loadFiles,
    };
  }

  async function applyStatsQuery(query) {
    filterInputEl.value = query;
    syncFilterHighlight();
    writeLogEntry(`[${threadName}] Stats tag clicked query="${query}"`);
    await runFilterQuery(query);
    const filteredPackets = getFilteredPackets();
    if (Array.isArray(filteredPackets) && filteredPackets.length > 0) {
      if (typeof syncTargetHostFromPackets === "function") {
        syncTargetHostFromPackets(filteredPackets);
      }
      setPacketsForHost(filteredPackets);
    }
  }

  function showStats(showOptions = {}) {
    try {
      if (typeof disposeHeatmapResize === "function") {
        disposeHeatmapResize();
        disposeHeatmapResize = null;
      }

      setActiveMainTab(mainTabStats);
      if (getJsonCapture() === "") {
        statusUpdate("Status: No JSON file loaded, please upload a file first");
        return;
      }
      statusUpdate("Status: Displaying capture statistics");
      writeLogEntry(`[${threadName}] User opened capture stats view`);

      documentRef.getElementById("packetInfoPane").style.display = "none";
      documentRef.getElementById("packetPayloadPane").style.display = "none";
      documentRef.getElementById("prev-btn").style.display = "none";
      documentRef.getElementById("next-btn").style.display = "none";
      documentRef.getElementById("summary_box").style.display = "none";
      documentRef.getElementById("list_box").style.display = "none";
      documentRef.getElementById("notes_box").style.display = "none";
      documentRef.getElementById("data_tools_box").style.display = "none";
      documentRef.getElementById("crypt_box").style.display = "none";
      documentRef.getElementById("keystore_box").style.display = "none";
      documentRef.getElementById("settings_box").style.display = "none";
      documentRef.getElementById("stats_box").style.display = "block";
      documentRef.getElementById("rightside").style.display = "none";

      const content = documentRef.getElementById("stats_content");
      content.replaceChildren();

      const subtabRow = documentRef.createElement("div");
      subtabRow.className = "stats-subtab-row";

      const statisticsTabBtn = documentRef.createElement("button");
      statisticsTabBtn.type = "button";
      statisticsTabBtn.className = "stats-subtab-btn active";
      statisticsTabBtn.textContent = "Statistics";

      const mapTabBtn = documentRef.createElement("button");
      mapTabBtn.type = "button";
      mapTabBtn.className = "stats-subtab-btn";
      mapTabBtn.textContent = "Map";

      subtabRow.appendChild(statisticsTabBtn);
      subtabRow.appendChild(mapTabBtn);
      content.appendChild(subtabRow);

      const statisticsPanel = documentRef.createElement("div");
      statisticsPanel.className = "stats-subtab-panel";

      const mapPanel = documentRef.createElement("div");
      mapPanel.className = "stats-subtab-panel";
      mapPanel.style.display = "none";

      content.appendChild(statisticsPanel);
      content.appendChild(mapPanel);

      const stats = buildCaptureStats(
        getCapturedPackets(),
        typeof getBookmarkCount === "function" ? getBookmarkCount() : 0,
      );
      if (!stats) {
        statisticsPanel.textContent = "No packet data available.";
        return;
      }

      let heatmapSectionRenderer = null;
      let heatmapSectionFocusLocation = null;
      const setActiveStatsSubtab = (tabId) => {
        const showMap = tabId === "map";
        statisticsTabBtn.classList.toggle("active", !showMap);
        mapTabBtn.classList.toggle("active", showMap);
        statisticsPanel.style.display = showMap ? "none" : "block";
        mapPanel.style.display = showMap ? "block" : "none";
        if (showMap && typeof heatmapSectionRenderer === "function") {
          heatmapSectionRenderer();
        }
      };

      statisticsTabBtn.addEventListener("click", () => setActiveStatsSubtab("statistics"));
      mapTabBtn.addEventListener("click", () => setActiveStatsSubtab("map"));

      // Defensive normalization so unusual packet schemas do not break stats rendering.
      const normalizeStringArray = (values) =>
        (Array.isArray(values) ? values : [])
          .map((value) => normalizeStatsTextValue(value))
          .filter((value) => value !== null);

      stats.protocols = normalizeStringArray(stats.protocols).map((proto) =>
        proto.toUpperCase(),
      );
      stats.networkProtocols = normalizeStringArray(stats.networkProtocols);
      stats.linkProtocols = normalizeStringArray(stats.linkProtocols);
      stats.decodedProtocols = normalizeStringArray(stats.decodedProtocols);
      stats.hosts = normalizeStringArray(stats.hosts);
      stats.hostnames = normalizeStringArray(stats.hostnames);
      stats.macVendors = normalizeStringArray(stats.macVendors);
      stats.mimeTypes = normalizeStringArray(stats.mimeTypes);
      stats.dataTypes = normalizeStringArray(stats.dataTypes);

      const overview = documentRef.createElement("div");
      overview.className = "stats-section";
      const ovHead = documentRef.createElement("div");
      ovHead.className = "stats-section-title";
      ovHead.textContent = "Capture Overview";
      overview.appendChild(ovHead);
      const overviewGrid = documentRef.createElement("div");
      overviewGrid.className = "stats-overview-grid";
      [
        `Total Packets: ${stats.totalPackets}`,
        `Bookmarked Packets: ${stats.bookmarkCount}`,
        `Undecodable Packets: ${stats.undecodableCount}`,
        `Total Streams: ${stats.totalStreams}`,
        `Longest Stream: ${stats.maxStreamLength} packets`,
        `Shortest Stream: ${stats.minStreamLength} packets`,
        `Average Stream Length: ${stats.avgStreamLength} packets`,
        `Unique Hosts Targeted: ${stats.hosts.length}`,
        `Encrypted Packets: ${stats.encryptedCount}`,
        `Unencrypted Packets: ${stats.unencryptedCount}`,
        `TCP Retransmissions: ${stats.retransmissionCount}`,
        `TCP Out-of-Order: ${stats.outOfOrderCount}`,
        `Unique Protocols: ${stats.protocols.length}`,
        `Unique Locations: ${stats.locations.length}`,
        `Total Traffic: ${stats.totalTraffic} bytes`,
        `Credentials Found: ${stats.uniqueCredentialCount}`,
      ].forEach((line) => {
        const kv = documentRef.createElement("div");
        kv.className = "stats-kv";
        kv.textContent = line;
        overviewGrid.appendChild(kv);
      });
      overview.appendChild(overviewGrid);
      statisticsPanel.appendChild(overview);

      const heatmapSection = createStatsHeatmapSection({
        documentRef,
        stats,
        getCapturedPackets,
        getFilteredPackets,
        getProjectionCalibrationSettings: () => getProjectionCalibration(getCurrentSettings),
        getCurrentSettings,
        applyStatsQuery,
      });
      if (heatmapSection) {
        mapPanel.appendChild(heatmapSection.section);
        heatmapSectionRenderer = heatmapSection.render;
        heatmapSectionFocusLocation =
          typeof heatmapSection.focusLocation === "function"
            ? heatmapSection.focusLocation
            : null;
        const rerenderHeatmap = () => {
          if (mapPanel.style.display !== "none") {
            heatmapSection.render();
          }
        };
        window.addEventListener("resize", rerenderHeatmap);
        disposeHeatmapResize = () => {
          window.removeEventListener("resize", rerenderHeatmap);
          if (typeof heatmapSection.dispose === "function") {
            heatmapSection.dispose();
          }
        };
      }

      const initialSubtab = showOptions?.openSubtab === "map" ? "map" : "statistics";
      setActiveStatsSubtab(initialSubtab);

      const focusLocation = showOptions?.focusLocation;
      if (
        initialSubtab === "map"
        && heatmapSectionFocusLocation
        && focusLocation
      ) {
        window.requestAnimationFrame(() => {
          void heatmapSectionFocusLocation(focusLocation);
        });
      }

      if (stats.undecodableCount > 0) {
        const undecodableSec = makeStatsSection({
          documentRef,
          title: "Undecodable Packets",
          items: [`Undecodable (${stats.undecodableCount})`],
          queryBuilder: () => `packet.proto: undecodable`,
          onQuery: applyStatsQuery,
        });
        if (undecodableSec) statisticsPanel.appendChild(undecodableSec);
      }

      const topTalkersSec = makeStatsSection({
        documentRef,
        title: "Top Talkers",
        items: stats.topTalkers.map((talker) => `${talker.ip} (${talker.count} packets)`),
        queryBuilder: (v) => `ip.src.addr: ${v.substr(0, v.indexOf(" "))} || ip.dst.addr: ${v.substr(0, v.indexOf(" "))}`,
        onQuery: applyStatsQuery,
      });
      if (topTalkersSec) statisticsPanel.appendChild(topTalkersSec);

      const carvableFilesSection = createCarvableFilesSection();
      statisticsPanel.appendChild(carvableFilesSection.section);
      void carvableFilesSection.loadFiles();

      const credsSec = makeStatsSection({
        documentRef,
        title: "Credentials Found",
        items: stats.uniqueCredentialCount > 0 ? stats.uniqueCredentials : [""],
        itemTitle: (item) =>
          item === "No credentials found"
            ? ""
            : "Click to open the keychain manager",
        onItemClick: (item) => {
          if (item === "No credentials found") return;
          const activeKeystorePanel = resolveKeystorePanel();
          if (!activeKeystorePanel) return;

          (async () => {
            if (typeof activeKeystorePanel.unlockPersistentKeystoreAndLoad === "function") {
              const unlocked = await activeKeystorePanel.unlockPersistentKeystoreAndLoad();
              if (!unlocked) return;
            }

            if (typeof activeKeystorePanel.showKeystoreWorkspace === "function") {
              activeKeystorePanel.showKeystoreWorkspace();
            }
          })();
        },
      });
      if (credsSec) statisticsPanel.appendChild(credsSec);

      // make the application protocols uppercase to be congruent with the rest of the protos
      stats.protocols = stats.protocols.map((proto) => proto.toUpperCase());
      const protoSec = makeStatsSection({
        documentRef,
        title: "Application Protocols",
        items: stats.protocols,
        queryBuilder: (v) => `application.proto: ${v.toLowerCase()}`,
        onQuery: applyStatsQuery,
      });
      if (protoSec) statisticsPanel.appendChild(protoSec);

      const networkProtoSec = makeStatsSection({
        documentRef,
        title: "Network/Transport/Link Protocols",
        items: stats.networkProtocols,
        queryBuilder: (v) => `network.proto: ${v.toLowerCase()} || link.proto: ${v.toLowerCase()} || decoded.proto: ${v.toLowerCase()} || transport.proto: ${v.toLowerCase()}`,
        onQuery: applyStatsQuery,
      });
      if (networkProtoSec) statisticsPanel.appendChild(networkProtoSec);

      const tpSec = makeStatsSection({
        documentRef,
        title: "Link Protocols",
        items: stats.linkProtocols,
        queryBuilder: (v) => `link.proto: ${v.toLowerCase()}`,
        onQuery: applyStatsQuery,
      });
      if (tpSec) statisticsPanel.appendChild(tpSec);

      const decodedProtoSec = makeStatsSection({
        documentRef,
        title: "Decoded Protocols",
        items: stats.decodedProtocols,
        queryBuilder: (v) => `decoded.proto: ${v.toLowerCase()}`,
        onQuery: applyStatsQuery,
      });
      if (decodedProtoSec) statisticsPanel.appendChild(decodedProtoSec);

      const arpOpSec = makeStatsSection({
        documentRef,
        title: "ARP/RARP Operations",
        items: stats.arpOperations,
        queryBuilder: (v) => `arp.op: ${v.toLowerCase()}`,
        onQuery: applyStatsQuery,
      });
      if (arpOpSec) statisticsPanel.appendChild(arpOpSec);

      const igmpTypeSec = makeStatsSection({
        documentRef,
        title: "IGMP Message Types",
        items: stats.igmpMessageTypes,
        queryBuilder: (v) => `igmp.type: ${v.toLowerCase()}`,
        onQuery: applyStatsQuery,
      });
      if (igmpTypeSec) statisticsPanel.appendChild(igmpTypeSec);

      const hostSec = makeStatsSection({
        documentRef,
        title: "All Hosts Addressed",
        items: stats.hosts,
        queryBuilder: (v) => `ip.src.addr: ${v} || ip.dst.addr: ${v}`,
        onQuery: applyStatsQuery,
      });
      if (hostSec) statisticsPanel.appendChild(hostSec);

      // make sure the ips here are not listed in stats.hosts, if they are, skip them
      const hostIpsSet = new Set(stats.hosts);
      const filteredHostnames = stats.hostnames.filter((hn) => {
        const hnAsIp = hn.replace(/^\[|\]$/g, ""); // Remove brackets from IPv6 addresses
        return !hostIpsSet.has(hnAsIp);
      });
      // also filter out any hostnames that have a "," comma in them, as they are likely
      // malformed and not useful for filtering
      const fullyFilteredHostnames = filteredHostnames.filter((hn) => !hn.includes(","));
      if (fullyFilteredHostnames.length > 0) {
        const filteredHnSec = makeStatsSection({
          documentRef,
          title: "Hostnames (DNS)",
          items: fullyFilteredHostnames,
          queryBuilder: (v) => `dns.qname: ${v}`,
          onQuery: applyStatsQuery,
        });
        if (filteredHnSec) statisticsPanel.appendChild(filteredHnSec);
      }
      //if (hnSec) content.appendChild(hnSec);

      if (stats.locations.length > 0) {
        const locItems = stats.locations.map(([place, count]) => `${place} (${count})`);
        const locSec = makeStatsSection({
          documentRef,
          title: "Physical Locations",
          items: locItems,
          queryBuilder: (v) => {
            // we should search by the city, which comes before a comma
            const city = v.split(" (")[0].split(",")[0].trim();
            return `loc.src.city: ${city} || loc.dst.city: ${city}`;
          },
          onQuery: applyStatsQuery,
        });
        if (locSec) statisticsPanel.appendChild(locSec);
      }

      const portSec = makeStatsSection({
        documentRef,
        title: "Ports Seen",
        items: stats.ports.map(String),
        queryBuilder: (v) => `(tcp.src.port: ${v} || tcp.dst.port: ${v}) || (udp.src.port: ${v} || udp.dst.port: ${v}) || (sctp.src.port: ${v} || sctp.dst.port: ${v})`,
        onQuery: applyStatsQuery,
      });
      if (portSec) statisticsPanel.appendChild(portSec);

      const macSec = makeStatsSection({
        documentRef,
        title: "MAC Vendors",
        items: stats.macVendors,
        queryBuilder: (v) => `eth.src.vendor: ${v}`,
        onQuery: applyStatsQuery,
      });
      if (macSec) statisticsPanel.appendChild(macSec);

      const mimeSec = makeStatsSection({
        documentRef,
        title: "MIME Types",
        items: stats.mimeTypes,
        queryBuilder: (v) => `mime.type: ${v}`,
        onQuery: applyStatsQuery,
      });
      if (mimeSec) statisticsPanel.appendChild(mimeSec);
      /*
      const dtSec = makeStatsSection({
        documentRef,
        title: "Data Types",
        items: stats.dataTypes.map((dt) => {
          const firstSix = dt.substring(0, 6);
          if (firstSix) { return stats.dataTypes.find((d) => d.startsWith(firstSix)); }
          return dt;
        }),
      });
      if (dtSec) statisticsPanel.appendChild(dtSec);
      */
    } catch (error) {
      const message = error?.stack || error?.message || String(error);
      writeLogEntry(`[${threadName}] Failed to render stats panel: ${message}`);
      statusUpdate("Status: Failed to render capture stats. See activity log for details.");
      const content = documentRef.getElementById("stats_content");
      if (content) {
        content.replaceChildren();
        content.textContent = "Unable to render stats for this capture.";
      }
    }
  }

  return {
    showStats,
    showStatsHeatmapLocation: (focusLocation) => {
      showStats({
        openSubtab: "map",
        focusLocation,
      });
    },
  };
}

module.exports = {
  id: "stats",
  createStatsPanel,
  buildCaptureStats,
};
