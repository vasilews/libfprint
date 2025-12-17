/* fpi-custom-match.h
 * 
 * Custom fingerprint matching using SIFT + geometric verification
 * 
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef FPI_CUSTOM_MATCH_H
#define FPI_CUSTOM_MATCH_H

#include <glib.h>

G_BEGIN_DECLS

/* Opaque structure for features */
typedef struct _FpiCustomFeatures FpiCustomFeatures;

/* Configuration */
#define FPI_CUSTOM_MIN_FEATURES     10
#define FPI_CUSTOM_MATCH_THRESHOLD  10

/**
 * fpi_custom_extract_features:
 * @image_data: Raw grayscale image data
 * @width: Image width
 * @height: Image height
 *
 * Extract SIFT features from fingerprint image.
 *
 * Returns: (transfer full): Features or NULL on error
 */
FpiCustomFeatures *fpi_custom_extract_features(const guint8 *image_data,
                                                gint          width,
                                                gint          height);

/**
 * fpi_custom_match:
 * @features1: First feature set
 * @features2: Second feature set
 *
 * Match two fingerprints using SIFT + geometric verification.
 *
 * Returns: Match score (>= FPI_CUSTOM_MATCH_THRESHOLD means match)
 */
gint fpi_custom_match(const FpiCustomFeatures *features1,
                      const FpiCustomFeatures *features2);

/**
 * fpi_custom_features_serialize:
 * @features: Features to serialize
 *
 * Serialize features for storage in FpPrint.
 *
 * Returns: (transfer full): Serialized data
 */
GBytes *fpi_custom_features_serialize(const FpiCustomFeatures *features);

/**
 * fpi_custom_features_deserialize:
 * @data: Serialized data
 *
 * Deserialize features from storage.
 *
 * Returns: (transfer full): Features or NULL on error
 */
FpiCustomFeatures *fpi_custom_features_deserialize(GBytes *data);

/**
 * fpi_custom_features_get_count:
 * @features: Features
 *
 * Get number of keypoints.
 *
 * Returns: Number of keypoints
 */
gsize fpi_custom_features_get_count(const FpiCustomFeatures *features);

/**
 * fpi_custom_features_free:
 * @features: Features to free
 *
 * Free features structure.
 */
void fpi_custom_features_free(FpiCustomFeatures *features);

G_END_DECLS

#endif /* FPI_CUSTOM_MATCH_H */

