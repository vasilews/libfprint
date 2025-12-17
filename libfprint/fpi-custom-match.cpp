/* fpi-custom-match.cpp
 * 
 * Custom fingerprint matching using SIFT + geometric verification
 * 
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "fpi-custom-match.h"

#include <opencv2/core.hpp>
#include <opencv2/features2d.hpp>
#include <opencv2/imgproc.hpp>
#include <vector>
#include <cmath>
#include <algorithm>
#include <cstring>

/* Matching parameters */
static constexpr double DISTANCE_RATIO   = 0.75;
static constexpr double LENGTH_THRESHOLD = 0.95;
static constexpr double ANGLE_THRESHOLD  = 0.05;

struct _FpiCustomFeatures
{
    std::vector<cv::KeyPoint> keypoints;
    cv::Mat                   descriptors;
    
    _FpiCustomFeatures() = default;
    ~_FpiCustomFeatures() = default;
    
    /* Non-copyable */
    _FpiCustomFeatures(const _FpiCustomFeatures&) = delete;
    _FpiCustomFeatures& operator=(const _FpiCustomFeatures&) = delete;
};

extern "C" {

FpiCustomFeatures *
fpi_custom_extract_features(const guint8 *image_data,
                            gint          width,
                            gint          height)
{
    if (!image_data || width <= 0 || height <= 0)
        return nullptr;

    try
    {
        /* Create Mat from raw data (no copy) */
        cv::Mat image(height, width, CV_8UC1, 
                      const_cast<guint8*>(image_data));
        
        /* Preprocessing */
        cv::Mat processed;
        
        /* Normalize contrast */
        cv::normalize(image, processed, 0, 255, cv::NORM_MINMAX, CV_8U);
        
        /* Optional: Apply CLAHE for better contrast */
        auto clahe = cv::createCLAHE(2.0, cv::Size(8, 8));
        clahe->apply(processed, processed);
        
        /* Extract SIFT features */
        auto sift = cv::SIFT::create(
            0,      /* nfeatures - 0 means no limit */
            3,      /* nOctaveLayers */
            0.04,   /* contrastThreshold */
            10,     /* edgeThreshold */
            1.6     /* sigma */
        );
        
        auto *features = new FpiCustomFeatures();
        sift->detectAndCompute(processed, cv::noArray(), 
                               features->keypoints, 
                               features->descriptors);
        
        return features;
    }
    catch (const std::exception& e)
    {
        g_warning("Feature extraction failed: %s", e.what());
        return nullptr;
    }
}

gint
fpi_custom_match(const FpiCustomFeatures *features1,
                 const FpiCustomFeatures *features2)
{
    if (!features1 || !features2)
        return 0;
    
    if (features1->keypoints.size() < FPI_CUSTOM_MIN_FEATURES ||
        features2->keypoints.size() < FPI_CUSTOM_MIN_FEATURES)
        return 0;
    
    if (features1->descriptors.empty() || features2->descriptors.empty())
        return 0;

    try
    {
        /* KNN matching with k=2 for ratio test */
        std::vector<std::vector<cv::DMatch>> knn_matches;
        auto matcher = cv::BFMatcher::create(cv::NORM_L2);
        matcher->knnMatch(features1->descriptors,
                          features2->descriptors,
                          knn_matches, 2);
        
        /* Apply Lowe's ratio test */
        std::vector<std::pair<cv::Point2f, cv::Point2f>> good_matches;
        good_matches.reserve(knn_matches.size());
        
        for (const auto &match : knn_matches)
        {
            if (match.size() < 2)
                continue;
                
            if (match[0].distance < DISTANCE_RATIO * match[1].distance)
            {
                auto pt1 = features1->keypoints[match[0].queryIdx].pt;
                auto pt2 = features2->keypoints[match[0].trainIdx].pt;
                
                /* Check for duplicates */
                bool is_duplicate = false;
                for (const auto &existing : good_matches)
                {
                    if (std::abs(existing.first.x - pt1.x) < 1e-3 &&
                        std::abs(existing.first.y - pt1.y) < 1e-3 &&
                        std::abs(existing.second.x - pt2.x) < 1e-3 &&
                        std::abs(existing.second.y - pt2.y) < 1e-3)
                    {
                        is_duplicate = true;
                        break;
                    }
                }
                
                if (!is_duplicate)
                    good_matches.emplace_back(pt1, pt2);
            }
        }
        
        if (good_matches.size() < FPI_CUSTOM_MIN_FEATURES)
            return static_cast<gint>(good_matches.size());
        
        /* Geometric verification */
        int max_consistent = 0;
        
        for (size_t i = 0; i < good_matches.size(); i++)
        {
            const auto &match1 = good_matches[i];
            std::vector<double> angles;
            angles.reserve(good_matches.size());
            
            for (size_t j = 0; j < good_matches.size(); j++)
            {
                if (i == j)
                    continue;
                
                const auto &match2 = good_matches[j];
                
                /* Vectors between matched points */
                double vec1_x = match1.first.x - match2.first.x;
                double vec1_y = match1.first.y - match2.first.y;
                double vec2_x = match1.second.x - match2.second.x;
                double vec2_y = match1.second.y - match2.second.y;
                
                double len1 = std::sqrt(vec1_x * vec1_x + vec1_y * vec1_y);
                double len2 = std::sqrt(vec2_x * vec2_x + vec2_y * vec2_y);
                
                /* Skip if vectors too short */
                if (len1 < 1e-6 || len2 < 1e-6)
                    continue;
                
                /* Check length ratio */
                double min_len = std::min(len1, len2);
                double max_len = std::max(len1, len2);
                
                if (min_len < LENGTH_THRESHOLD * max_len)
                    continue;
                
                /* Calculate angle between vectors */
                double cross = vec1_x * vec2_y - vec1_y * vec2_x;
                double dot = vec1_x * vec2_x + vec1_y * vec2_y;
                double angle = std::atan2(cross, dot);
                
                angles.push_back(angle);
            }
            
            /* Count consistent angles */
            for (size_t a = 0; a < angles.size(); a++)
            {
                int count = 1;
                double angle1 = angles[a];
                
                for (size_t b = 0; b < angles.size(); b++)
                {
                    if (a == b)
                        continue;
                    
                    double diff = std::abs(angle1 - angles[b]);
                    
                    /* Handle angle wrap-around */
                    if (diff < ANGLE_THRESHOLD || 
                        (2.0 * M_PI - diff) < ANGLE_THRESHOLD)
                    {
                        count++;
                    }
                }
                
                max_consistent = std::max(max_consistent, count);
            }
        }
        
        return max_consistent;
    }
    catch (const std::exception& e)
    {
        g_warning("Matching failed: %s", e.what());
        return 0;
    }
}

GBytes *
fpi_custom_features_serialize(const FpiCustomFeatures *features)
{
    if (!features)
        return nullptr;
    
    try
    {
        /*
         * Format:
         * [4 bytes] magic (0x46504331 = "FPC1")
         * [4 bytes] version (1)
         * [4 bytes] num_keypoints
         * [4 bytes] desc_rows
         * [4 bytes] desc_cols
         * [4 bytes] desc_type
         * [num_keypoints * 28 bytes] keypoints (7 floats each)
         * [variable] descriptors data
         */
        
        const guint32 magic = 0x46504331;  /* "FPC1" */
        const guint32 version = 1;
        guint32 num_kp = static_cast<guint32>(features->keypoints.size());
        guint32 desc_rows = static_cast<guint32>(features->descriptors.rows);
        guint32 desc_cols = static_cast<guint32>(features->descriptors.cols);
        guint32 desc_type = static_cast<guint32>(features->descriptors.type());
        
        gsize kp_size = num_kp * sizeof(float) * 7;
        gsize desc_size = 0;
        
        if (!features->descriptors.empty())
        {
            desc_size = features->descriptors.total() * 
                        features->descriptors.elemSize();
        }
        
        gsize header_size = sizeof(guint32) * 6;
        gsize total_size = header_size + kp_size + desc_size;
        
        guint8 *buffer = static_cast<guint8*>(g_malloc(total_size));
        guint8 *ptr = buffer;
        
        /* Header */
        memcpy(ptr, &magic, sizeof(guint32)); ptr += sizeof(guint32);
        memcpy(ptr, &version, sizeof(guint32)); ptr += sizeof(guint32);
        memcpy(ptr, &num_kp, sizeof(guint32)); ptr += sizeof(guint32);
        memcpy(ptr, &desc_rows, sizeof(guint32)); ptr += sizeof(guint32);
        memcpy(ptr, &desc_cols, sizeof(guint32)); ptr += sizeof(guint32);
        memcpy(ptr, &desc_type, sizeof(guint32)); ptr += sizeof(guint32);
        
        /* Keypoints */
        for (const auto &kp : features->keypoints)
        {
            float data[7] = {
                kp.pt.x, 
                kp.pt.y, 
                kp.size, 
                kp.angle,
                kp.response, 
                static_cast<float>(kp.octave), 
                static_cast<float>(kp.class_id)
            };
            memcpy(ptr, data, sizeof(data));
            ptr += sizeof(data);
        }
        
        /* Descriptors */
        if (desc_size > 0)
        {
            if (features->descriptors.isContinuous())
            {
                memcpy(ptr, features->descriptors.data, desc_size);
            }
            else
            {
                for (int i = 0; i < features->descriptors.rows; i++)
                {
                    gsize row_size = static_cast<gsize>(
                        features->descriptors.cols * 
                        features->descriptors.elemSize()
                    );
                    memcpy(ptr, features->descriptors.ptr(i), row_size);
                    ptr += row_size;
                }
            }
        }
        
        return g_bytes_new_take(buffer, total_size);
    }
    catch (const std::exception& e)
    {
        g_warning("Serialization failed: %s", e.what());
        return nullptr;
    }
}

FpiCustomFeatures *
fpi_custom_features_deserialize(GBytes *data)
{
    if (!data)
        return nullptr;
    
    try
    {
        gsize size;
        const guint8 *buffer = static_cast<const guint8*>(
            g_bytes_get_data(data, &size)
        );
        const guint8 *ptr = buffer;
        
        /* Minimum size check */
        gsize header_size = sizeof(guint32) * 6;
        if (size < header_size)
            return nullptr;
        
        /* Header */
        guint32 magic, version, num_kp, desc_rows, desc_cols, desc_type;
        
        memcpy(&magic, ptr, sizeof(guint32)); ptr += sizeof(guint32);
        memcpy(&version, ptr, sizeof(guint32)); ptr += sizeof(guint32);
        memcpy(&num_kp, ptr, sizeof(guint32)); ptr += sizeof(guint32);
        memcpy(&desc_rows, ptr, sizeof(guint32)); ptr += sizeof(guint32);
        memcpy(&desc_cols, ptr, sizeof(guint32)); ptr += sizeof(guint32);
        memcpy(&desc_type, ptr, sizeof(guint32)); ptr += sizeof(guint32);
        
        /* Validate magic */
        if (magic != 0x46504331)
        {
            g_warning("Invalid magic: 0x%08X", magic);
            return nullptr;
        }
        
        /* Validate version */
        if (version != 1)
        {
            g_warning("Unsupported version: %u", version);
            return nullptr;
        }
        
        /* Validate sizes */
        gsize kp_size = num_kp * sizeof(float) * 7;
        if (size < header_size + kp_size)
        {
            g_warning("Buffer too small for keypoints");
            return nullptr;
        }
        
        auto *features = new FpiCustomFeatures();
        
        /* Keypoints */
        features->keypoints.reserve(num_kp);
        for (guint32 i = 0; i < num_kp; i++)
        {
            float data[7];
            memcpy(data, ptr, sizeof(data));
            ptr += sizeof(data);
            
            cv::KeyPoint kp;
            kp.pt.x = data[0];
            kp.pt.y = data[1];
            kp.size = data[2];
            kp.angle = data[3];
            kp.response = data[4];
            kp.octave = static_cast<int>(data[5]);
            kp.class_id = static_cast<int>(data[6]);
            
            features->keypoints.push_back(kp);
        }
        
        /* Descriptors */
        if (desc_rows > 0 && desc_cols > 0)
        {
            features->descriptors = cv::Mat(
                static_cast<int>(desc_rows), 
                static_cast<int>(desc_cols), 
                static_cast<int>(desc_type)
            );
            
            gsize desc_size = features->descriptors.total() * 
                              features->descriptors.elemSize();
            
            if (size >= header_size + kp_size + desc_size)
            {
                memcpy(features->descriptors.data, ptr, desc_size);
            }
            else
            {
                g_warning("Buffer too small for descriptors");
                delete features;
                return nullptr;
            }
        }
        
        return features;
    }
    catch (const std::exception& e)
    {
        g_warning("Deserialization failed: %s", e.what());
        return nullptr;
    }
}

gsize
fpi_custom_features_get_count(const FpiCustomFeatures *features)
{
    if (!features)
        return 0;
    return features->keypoints.size();
}

void
fpi_custom_features_free(FpiCustomFeatures *features)
{
    delete features;
}

} /* extern "C" */

