/**
 * Dựng dữ liệu cần ký (sign bytes) cho từng thao tác.
 * Cách dựng giống hệt @cheqd/sdk 5.5.1 (utils.js: createMsg...PayloadToSign, signer.js: sign...DidDocTx),
 * đã được kiểm chứng bằng các script thử nghiệm trên localnet.
 */
import { DIDModule } from '@cheqd/sdk';
import {
  MsgCreateDidDocPayload,
  MsgUpdateDidDocPayload,
  MsgDeactivateDidDocPayload,
} from '@cheqd/ts-proto/cheqd/did/v2/index.js';
import { ModuleError } from './config.js';

/** Create và Update: mã hóa protobuf toàn bộ DID Document kèm versionId */
export async function buildDocSignBytes(kind: 'create' | 'update', didDocument: any, versionId: string): Promise<Uint8Array> {
  const { valid, error, protobufVerificationMethod, protobufService } =
    await (DIDModule as any).validateSpecCompliantPayload(didDocument);
  if (!valid) throw new ModuleError(422, 'INVALID_DID_DOCUMENT', `DID Document không hợp lệ theo đặc tả: ${error}`);

  const msgType: any = kind === 'create' ? MsgCreateDidDocPayload : MsgUpdateDidDocPayload;
  const payload = msgType.fromPartial({
    context: didDocument['@context'],
    id: didDocument.id,
    controller: didDocument.controller,
    verificationMethod: protobufVerificationMethod,
    authentication: didDocument.authentication,
    assertionMethod: didDocument.assertionMethod,
    capabilityInvocation: didDocument.capabilityInvocation,
    capabilityDelegation: didDocument.capabilityDelegation,
    keyAgreement: didDocument.keyAgreement,
    service: protobufService,
    alsoKnownAs: didDocument.alsoKnownAs,
    versionId,
  });
  return msgType.encode(payload).finish();
}

/** Deactivate: chỉ mã hóa id và versionId */
export function buildDeactivateSignBytes(did: string, versionId: string): Uint8Array {
  return MsgDeactivateDidDocPayload.encode(MsgDeactivateDidDocPayload.fromPartial({ id: did, versionId })).finish();
}
