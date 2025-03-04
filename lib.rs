#![cfg_attr(not(feature = "std"), no_std, no_main)]

use sp_core::offchain::Timestamp;

#[ink::contract]
mod pay_channel {

    #[ink(storage)]
    pub struct PaymentChannel {
        sender: AccountId,
        recipient: AccountId,
        expiration: Option<Timestamp>,
        withdrawn: Balance,
        close_duration: Timestamp,
    }

    #[derive(Debug, PartialEq, Eq)]
    #[ink::scale_derive(Decode, Encode, TypeInfo)]
    #[allow(clippy::cast_possible_truncation)]
    pub enum Error {
        CallerIsNotSender,
        CallerIsNotRecipient,
        AmmountIsLessThanWithdrawn,
        TransferFailed,
        NotYetExpired,
        InvalidSignature,
    }

    pub type Result<T> = core::result::Result<T, Error>;

    #[ink(event)]
    pub struct SenderCloseStarted {
        expiration: Timestamp,
        close_duration: Timestamp,
    }

    impl PaymentChannel {

        #[ink(constructor)]
        pub fn new(
            recipient:AccountId,
            close_duration: Timestamp
        ) -> Self {
           Self {
            sender : Self::env().caller(),
            recipient,
            expiration: None,
            withdrawn: 0,
            close_duration,
           }
        }

        #[ink(message)]
        pub fn close(
            &mut self, 
            amount: Balance, 
            signature: [u8; 65]
        ) -> Result<()> {
            self.close_inner(amount, signature)?;
            self.env().terminate_contract(self.sender);
        }

        /// We split this out in order to make testing `close` simpler.
        fn close_inner(
            &mut self, 
            amount: Balance, 
            signature: [u8; 65]) -> Result<()> {
            if self.env().caller() != self.recipient {
                return Err(Error::CallerIsNotRecipient)
            }

            if amount < self.withdrawn {
                return Err(Error::AmmountIsLessThanWithdrawn)
            }

            // Signature validation
            if !self.is_signature_valid(amount, signature) {
                return Err(Error::InvalidSignature)
            }

            // We checked that amount >= self.withdrawn
            #[allow(clippy::arithmetic_side_effects)]
            self.env()
                .transfer(self.recipient, amount - self.withdrawn)
                .map_err(|_| Error::TransferFailed)?;

            Ok(())
        }

        #[ink(message)]
        pub fn start_sender_close(
            &mut self
        ) -> Result<()> {
            if self.env().caller() != self.sender {
                return Err(Error::CallerIsNotSender)
            }

            let now = self.env().block_timestamp();
            let expiration = now.checked_add(self.close_duration).unwrap();

            self.env().emit_event(SenderCloseStarted {
                expiration,
                close_duration: self.close_duration,
            });

            self.expiration = Some(expiration);

            Ok(())
        }

        #[ink(message)]
        pub fn clain_timeout(
            &mut self
        ) -> Result<()> {
            match self.expiration{
                Some(expiration) => {
                    let now = self.env().block_timestamp();
                    if now < expiration {
                        return Err(Error::NotYetExpired)
                    }

                    self.env().terminate_contract(self.sender);
                } 

                None => Err(Error::NotYetExpired)
            }
        }

        #[ink(message)]
        pub fn withdrawn(
            &mut self,
            amount:Balance,
            signature:[u8;65],
        ) -> Result<()> {
            if self.env().caller() != self.recipient {
                return Err(Error::CallerIsNotRecipient)
            }

            if !self.is_signature_valid(amount,signature){
                return Err(Error::InvalidSignature)
            }

            if amount < self.withdrawn {
                return Err(Error::AmmountIsLessThanWithdrawn)
            }

            #[allow(clippy::arithmetic_side_effects)]
            let amount_to_withdraw = amount - self.withdrawn;
            self.withdrawn.checked_add(amount_to_withdraw).unwrap();

            self.env()
                .transfer(self.recipient, amount_to_withdraw)
                .map_err(|_| Error::TransferFailed)?;

            Ok(())
        }

        #[ink(message)]
        pub fn get_sender(&self) -> AccountId {
            self.sender
        }

        #[ink(message)]
        pub fn get_recipient(&self) -> AccountId {
            self.recipient
        }

        #[ink(message)]
        pub fn get_expiration(&self) -> Option<Timestamp> {
           self.expiration
        }

        #[ink(message)]
        pub fn get_withdrawn(&self) -> Balance {
            self.withdrawn
        }

        #[ink(message)]
        pub fn get_close_duration(&self) -> Timestamp {
            self.close_duration
        }

        #[ink(message)]
        pub fn get_balance(&self) -> Balance {
            self.env().balance()
        }

    }

    #[ink(impl)]
    impl PaymentChannel {
        fn is_signature_valid(
            &self,
            amount: Balance,
            signature: [u8; 65]
        ) -> bool {
            let encodable = (self.env().account_id(), amount);
            let mut message = <ink::env::hash::Sha2x256 as ink::env::hash::HashOutput>::Type::default();
            ink::env::hash_encoded::<ink::env::hash::Sha2x256, _>(
                &encodable,
                &mut message,
            );

            let mut pub_key = [0; 33];
            ink::env::ecdsa_recover(
                &signature, 
                &message,
                &mut pub_key
            ).unwrap_or_else(|err| panic! ("recover failed : {err:?}"));
            let mut signature_account_id = [0; 32];
            <ink::env::hash::Blake2x256 as ink::env::hash::CryptoHash>::hash(
                &pub_key,
                &mut signature_account_id
            );

            self.recipient == signature_account_id.into()
        }
    }
}


