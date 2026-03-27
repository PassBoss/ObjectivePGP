//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import <Foundation/Foundation.h>
#import <ObjectivePGP/PGPTypes.h>
#import <ObjectivePGP/PGPKey.h>

NS_ASSUME_NONNULL_BEGIN

NS_SWIFT_NAME(KeyGenerator) @interface PGPKeyGenerator : NSObject

@property (nonatomic) int keyBitsLength;
@property (nonatomic) PGPPublicKeyAlgorithm keyAlgorithm;
@property (nonatomic) PGPSymmetricAlgorithm cipherAlgorithm;
@property (nonatomic) PGPHashAlgorithm hashAlgorithm;
@property (nonatomic) PGPCurve curveKind;
@property (nonatomic) UInt8 version;
@property (nonatomic) NSDate *createDate;

/// S2K coded count byte (RFC 4880 §3.7.1.3, range 0–255).
/// The byte encodes how many bytes of data are hashed to derive the key.
/// Byte 215 (default) → ~12M bytes hashed. Byte 243 → ~40M bytes hashed (≥600k SHA-256 rounds).
/// Only used when generating passphrase-protected keys.
/// Values below 96 (~1k SHA-256 rounds) offer weak protection and should be avoided.
@property (nonatomic, readonly) UInt8 s2kIterationsCount;

- (PGPKey *)generateFor:(NSString *)userID passphrase:(nullable NSString *)passphrase;

- (instancetype)initWithAlgorithm:(PGPPublicKeyAlgorithm)algorithm keyBitsLength:(int)bits cipherAlgorithm:(PGPSymmetricAlgorithm)cipherAlgorithm hashAlgorithm:(PGPHashAlgorithm)hashAlgorithm;

- (instancetype)initWithAlgorithm:(PGPPublicKeyAlgorithm)algorithm keyBitsLength:(int)bits cipherAlgorithm:(PGPSymmetricAlgorithm)cipherAlgorithm hashAlgorithm:(PGPHashAlgorithm)hashAlgorithm s2kIterationsCount:(UInt8)s2kIterationsCount;

+ (nullable PGPKey *)buildKey:(nullable PGPKey *)key withPassphrase:(nullable NSString *)passphrase;
+ (nullable PGPKey *)buildKey:(nullable PGPKey *)key withPassphrase:(nullable NSString *)passphrase s2kIterationsCount:(UInt8)s2kIterationsCount;

@end

NS_ASSUME_NONNULL_END
