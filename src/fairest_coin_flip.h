#ifndef FAIREST_COIN_FLIP_H
#define FAIREST_COIN_FLIP_H

/**
 * @brief Signs a plain text proposal using S/MIME and writes the signed message to a file.
 * @param proposal_text The plain text proposal.
 * @param certificate_nickname The nickname of the certificate used for signing.
 * @param output_file_path The path to the file where the signed message will be written.
 * @return 1 on success, 0 on failure.
 */
int sign_proposal(const char *proposal_text, const char *certificate_nickname, const char *output_file_path);

/**
 * @brief Creates an S/MIME reveal document from plain text, signs it, and writes the signed message to a file.
 * @param reveal_text The plain text reveal document.
 * @param certificate_nickname The nickname of the certificate used for signing.
 * @param output_file_path The path to the file where the signed message will be written.
 * @return 1 on success, 0 on failure.
 */
int create_smime_reveal_document(const char *reveal_text, const char *certificate_nickname, const char *output_file_path);

/**
 * @brief Extracts the number of choices listed in the S/MIME distributed proposal and the first number in the list.
 * @param signed_proposal The signed proposal text.
 * @param certificate_nickname The nickname of the certificate used for verification.
 * @param first_number Pointer to store the first number in the list.
 * @return The number of choices in the enumerated list, or -1 on failure.
 */
int extract_number_of_choices(const char *signed_proposal, const char *certificate_nickname, int *first_number);

/**
 * @brief Calculates the result of the coin flip or dice roll based on the reveal numbers and the proposal.
 * @param signed_proposal The signed proposal text.
 * @param certificate_nickname The nickname of the certificate used for verification.
 * @param reveal_numbers An array of reveal numbers chosen by the participants.
 * @param num_participants The number of participants.
 * @return The result of the coin flip or dice roll, or -1 on failure.
 */
int calculate_result(const char *signed_proposal, const char *certificate_nickname, int *reveal_numbers, int num_participants);

/**
 * @brief Verifies if a reveal document is signed by one of the public keys enumerated in the other proposal MIME parts.
 * @param reveal_document The reveal document to verify.
 * @param signed_proposal The signed proposal containing the enumerated public keys.
 * @return The index of the matching public key, or -1 if it's not signed by any of them.
 */
int verify_reveal_signature(const char *reveal_document, const char *signed_proposal);

#endif // FAIREST_COIN_FLIP_H

