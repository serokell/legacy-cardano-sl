{-# LANGUAGE TypeFamilies #-}

-- | Wallet redemption

module Pos.Wallet.Web.Methods.Redeem
       ( redeemAda
       , redeemAdaPaperVend
       , redeemAdaSimple
       , redeemAdaPaperVendSimple
       ) where

import qualified Prelude                        as Prelude
import           Universum

import qualified Cardano.Crypto.Wallet          as CC
import           Crypto.Random                  (MonadRandom)
import           Data.ByteString.Base58         (bitcoinAlphabet, decodeBase58)
import qualified Serokell.Util.Base64           as B64

import           Pos.Aeson.ClientTypes          ()
import           Pos.Aeson.WalletBackup         ()
import           Pos.Client.Txp.Addresses       (MonadAddresses)
import           Pos.Client.Txp.History         (TxHistoryEntry (..))
import           Pos.Communication              (SendActions (..), prepareRedemptionTx, prepareRedemptionTxSimple)
import           Pos.Core                       (Timestamp (..), getCurrentTimestamp)
import           Pos.Crypto                     (PassPhrase, aesDecrypt, deriveAesKeyBS, EncryptedSecretKey (..),
                                                 hash, mkEncSecret, redeemDeterministicKeyGen)
import           Pos.Txp.Core                   (TxAux (..), TxOut (..))
import           Pos.Util                       (maybeThrow)
import           Pos.Util.BackupPhrase          (toSeed)
import           Pos.Wallet.KeyStorage          (AllUserSecrets (..))
import           Pos.Wallet.Web.Account         (GenSeed (..))
import           Pos.Wallet.Web.ClientTypes     (AccountId (..), CAccountId (..), CAddress (..),
                                                 CPaperVendWalletRedeem (..), CTx (..),
                                                 CWalletRedeem (..), addressToCId)
import           Pos.Wallet.Web.Error           (WalletError (..))
import           Pos.Wallet.Web.Methods.History (addHistoryTx, constructCTx, constructCTxSimple,
                                                 getCurChainDifficulty)
import qualified Pos.Wallet.Web.Methods.Logic   as L
import           Pos.Wallet.Web.Methods.Txp     (rewrapTxError, submitAndSaveNewPtx)
import           Pos.Wallet.Web.Mode            (MonadWalletWebMode)
import           Pos.Wallet.Web.Pending         (mkPendingTx)
import           Pos.Wallet.Web.State           (AddressLookupMode (Ever))
import           Pos.Wallet.Web.Tracking        (fixingCachedAccModifier)
import           Pos.Wallet.Web.Util            (decodeCTypeOrFail, getWalletAddrsSet)


redeemAda
    :: (MonadWalletWebMode m, MonadAddresses m)
    => SendActions m -> PassPhrase -> CWalletRedeem -> m CTx
redeemAda sendActions passphrase CWalletRedeem {..} = do
    seedBs <- maybe invalidBase64 pure
        -- NOTE: this is just safety measure
        $ rightToMaybe (B64.decode crSeed) <|> rightToMaybe (B64.decodeUrl crSeed)
    redeemAdaInternal sendActions passphrase crWalletId seedBs
  where
    invalidBase64 =
        throwM . RequestError $ "Seed is invalid base64(url) string: " <> crSeed

-- Decrypts certificate based on:
--  * https://github.com/input-output-hk/postvend-app/blob/master/src/CertGen.hs#L205
--  * https://github.com/input-output-hk/postvend-app/blob/master/src/CertGen.hs#L160
redeemAdaPaperVend
    :: (MonadWalletWebMode m, MonadAddresses m)
    => SendActions m
    -> PassPhrase
    -> CPaperVendWalletRedeem
    -> m CTx
redeemAdaPaperVend sendActions passphrase CPaperVendWalletRedeem {..} = do
    seedEncBs <- maybe invalidBase58 pure
        $ decodeBase58 bitcoinAlphabet $ encodeUtf8 pvSeed
    aesKey <- either invalidMnemonic pure
        $ deriveAesKeyBS <$> toSeed pvBackupPhrase
    seedDecBs <- either decryptionFailed pure
        $ aesDecrypt seedEncBs aesKey
    redeemAdaInternal sendActions passphrase pvWalletId seedDecBs
  where
    invalidBase58 =
        throwM . RequestError $ "Seed is invalid base58 string: " <> pvSeed
    invalidMnemonic e =
        throwM . RequestError $ "Invalid mnemonic: " <> toText e
    decryptionFailed e =
        throwM . RequestError $ "Decryption failed: " <> show e

redeemAdaInternal
    :: (MonadWalletWebMode m, MonadAddresses m)
    => SendActions m
    -> PassPhrase
    -> CAccountId
    -> ByteString
    -> m CTx
redeemAdaInternal SendActions {..} passphrase cAccId seedBs = do
    (_, redeemSK) <- maybeThrow (RequestError "Seed is not 32-byte long") $
                     redeemDeterministicKeyGen seedBs
    accId <- decodeCTypeOrFail cAccId
    -- new redemption wallet
    _ <- fixingCachedAccModifier L.getAccount accId

    dstAddr <- decodeCTypeOrFail . cadId =<<
               L.newAddress RandomSeed passphrase accId
    th <- rewrapTxError "Cannot send redemption transaction" $ do
        (txAux, redeemAddress, redeemBalance) <-
                prepareRedemptionTx redeemSK dstAddr

        ts <- Just <$> getCurrentTimestamp
        let tx = taTx txAux
            txHash = hash tx
            txInputs = [TxOut redeemAddress redeemBalance]
            th = THEntry txHash tx Nothing txInputs [dstAddr] ts
            dstWallet = aiWId accId
        ptx <- mkPendingTx dstWallet txHash txAux th

        th <$ submitAndSaveNewPtx enqueueMsg ptx

    -- add redemption transaction to the history of new wallet
    let cWalId = aiWId accId
    addHistoryTx cWalId th
    cWalAddrs <- getWalletAddrsSet Ever cWalId
    diff <- getCurChainDifficulty
    fst <$> constructCTx cWalId cWalAddrs diff th

redeemAdaSimple
    :: (MonadThrow m, MonadCatch m, MonadIO m, MonadRandom m)
    => PassPhrase -> CWalletRedeem -> m CTx
redeemAdaSimple passphrase CWalletRedeem {..} = do
    seedBs <- maybe invalidBase64 pure
        -- NOTE: this is just safety measure
        $ rightToMaybe (B64.decode crSeed) <|> rightToMaybe (B64.decodeUrl crSeed)
    redeemAdaInternalSimple passphrase crWalletId seedBs
  where
    invalidBase64 =
        throwM . RequestError $ "Seed is invalid base64(url) string: " <> crSeed

-- Decrypts certificate based on:
--  * https://github.com/input-output-hk/postvend-app/blob/master/src/CertGen.hs#L205
--  * https://github.com/input-output-hk/postvend-app/blob/master/src/CertGen.hs#L160
redeemAdaPaperVendSimple
    :: (MonadThrow m, MonadCatch m, MonadIO m, MonadRandom m)
    => PassPhrase -> CPaperVendWalletRedeem -> m CTx
redeemAdaPaperVendSimple passphrase CPaperVendWalletRedeem {..} = do
    seedEncBs <- maybe invalidBase58 pure
        $ decodeBase58 bitcoinAlphabet $ encodeUtf8 pvSeed
    aesKey <- either invalidMnemonic pure
        $ deriveAesKeyBS <$> toSeed pvBackupPhrase
    seedDecBs <- either decryptionFailed pure
        $ aesDecrypt seedEncBs aesKey
    redeemAdaInternalSimple passphrase pvWalletId seedDecBs
  where
    invalidBase58 =
        throwM . RequestError $ "Seed is invalid base58 string: " <> pvSeed
    invalidMnemonic e =
        throwM . RequestError $ "Invalid mnemonic: " <> toText e
    decryptionFailed e =
        throwM . RequestError $ "Decryption failed: " <> show e

redeemAdaInternalSimple
    :: (MonadThrow m, MonadCatch m, MonadIO m, MonadRandom m)
    => PassPhrase -> CAccountId -> ByteString -> m CTx
redeemAdaInternalSimple passphrase cAccId seedBs = do
    (_, redeemSK) <- maybeThrow (RequestError "Seed is not 32-byte long") $
                     redeemDeterministicKeyGen seedBs
    accId <- decodeCTypeOrFail cAccId
    let xprv = CC.generate seedBs passphrase
    secrets <- AllUserSecrets . one <$> mkEncSecret passphrase xprv
    dstAddr <- decodeCTypeOrFail . cadId =<<
               L.newAddressSimple secrets RandomSeed passphrase accId
    th <- rewrapTxError "Cannot send redemption transaction" $ do
        (txAux, redeemAddress, redeemBalance) <-
                prepareRedemptionTxSimple redeemSK dstAddr

        let ts = Just $ Timestamp 123456789
        let tx = taTx txAux
            txHash = hash tx
            txInputs = [TxOut redeemAddress redeemBalance]
            th = THEntry txHash tx Nothing txInputs [dstAddr] ts

        pure th

    let cWalAddrs = one $ addressToCId dstAddr
    let diff = 0
    fst <$> constructCTxSimple cWalAddrs diff th
