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

/// S2K iteration count byte (RFC 4880 §3.7.1.3 coded value, 0–255).
/// Default is 215 (~12M bytes hashed). Set to 243 for ≥600k SHA-256 rounds.
/// Only used when generating passphrase-protected keys.
@property (nonatomic, readonly) UInt8 s2kIterationsCount;

- (PGPKey *)generateFor:(NSString *)userID passphrase:(nullable NSString *)passphrase;

- (instancetype)initWithAlgorithm:(PGPPublicKeyAlgorithm)algorithm keyBitsLength:(int)bits cipherAlgorithm:(PGPSymmetricAlgorithm)cipherAlgorithm hashAlgorithm:(PGPHashAlgorithm)hashAlgorithm;

- (instancetype)initWithAlgorithm:(PGPPublicKeyAlgorithm)algorithm keyBitsLength:(int)bits cipherAlgorithm:(PGPSymmetricAlgorithm)cipherAlgorithm hashAlgorithm:(PGPHashAlgorithm)hashAlgorithm s2kIterationsCount:(UInt8)s2kIterationsCount;

+ (nullable PGPKey *)buildKey:(nullable PGPKey *)key withPassphrase:(nullable NSString *)passphrase;
+ (nullable PGPKey *)buildKey:(nullable PGPKey *)key withPassphrase:(nullable NSString *)passphrase s2kIterationsCount:(UInt8)s2kIterationsCount;

@end

NS_ASSUME_NONNULL_END
