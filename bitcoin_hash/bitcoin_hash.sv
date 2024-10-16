module bitcoin_hash #(
    parameter integer NUM_OF_WORDS = 19
) (
    input  logic        clk,             // Clock signal
    reset_n,  // Active-low reset signal
    start,  // Start signal for initiating hashing
    input  logic [15:0] message_addr,    // Memory address of the message to hash
    output_addr,  // Output address for the result
    output logic        done,            // Done signal indicating hash completion
    mem_clk,  // Memory clock output
    mem_we,  // Memory write enable
    output logic [15:0] mem_addr,        // Memory address for read/write operations
    output logic [31:0] mem_write_data,  // Data to be written to memory
    input  logic [31:0] mem_read_data    // Data read from memory
);

  parameter num_nonces = 16;  // Number of parallel nonces for hashing

  // States for state machine
  enum logic [2:0] {
    IDLE,          // Idle state
    START_BUFFER,  // Start buffer for memory read
    START,         // Start hashing
    READ,          // Read message from memory
    FINISH,        // Final state to complete the hash
    COMPUTE,       // Compute the hash
    WRITE_BUFFER,  // Write buffer to memory
    WRITE          // Write results to memory
  } state;

  // SHA-256 constants (the first 32 bits of the fractional parts of the cube roots of the first 64 primes)
  parameter int k[64] = '{
      32'h428a2f98,
      32'h71374491,
      32'hb5c0fbcf,
      32'he9b5dba5,
      32'h3956c25b,
      32'h59f111f1,
      32'h923f82a4,
      32'hab1c5ed5,
      32'hd807aa98,
      32'h12835b01,
      32'h243185be,
      32'h550c7dc3,
      32'h72be5d74,
      32'h80deb1fe,
      32'h9bdc06a7,
      32'hc19bf174,
      32'he49b69c1,
      32'hefbe4786,
      32'h0fc19dc6,
      32'h240ca1cc,
      32'h2de92c6f,
      32'h4a7484aa,
      32'h5cb0a9dc,
      32'h76f988da,
      32'h983e5152,
      32'ha831c66d,
      32'hb00327c8,
      32'hbf597fc7,
      32'hc6e00bf3,
      32'hd5a79147,
      32'h06ca6351,
      32'h14292967,
      32'h27b70a85,
      32'h2e1b2138,
      32'h4d2c6dfc,
      32'h53380d13,
      32'h650a7354,
      32'h766a0abb,
      32'h81c2c92e,
      32'h92722c85,
      32'ha2bfe8a1,
      32'ha81a664b,
      32'hc24b8b70,
      32'hc76c51a3,
      32'hd192e819,
      32'hd6990624,
      32'hf40e3585,
      32'h106aa070,
      32'h19a4c116,
      32'h1e376c08,
      32'h2748774c,
      32'h34b0bcb5,
      32'h391c0cb3,
      32'h4ed8aa4a,
      32'h5b9cca4f,
      32'h682e6ff3,
      32'h748f82ee,
      32'h78a5636f,
      32'h84c87814,
      32'h8cc70208,
      32'h90befffa,
      32'ha4506ceb,
      32'hbef9a3f7,
      32'hc67178f2
  };

  assign mem_clk = clk;  // Assign memory clock signal

  // Hash variables for each nonce
  logic [31:0]
      h0[num_nonces],
      h1[num_nonces],
      h2[num_nonces],
      h3[num_nonces],
      h4[num_nonces],
      h5[num_nonces],
      h6[num_nonces],
      h7[num_nonces];

  logic [31:0] wt[num_nonces];  // Message schedule (wt)
  logic [31:0]
      w[num_nonces][16], h[num_nonces][8];  // Working variables for message and hash values
  logic [31:0] nonce, t1, t2;  // Nonce and loop counters
  logic [15:0] i;  // Index variable
  logic        first;  // Flag for first read operation
  logic        second;  // Flag for second operation phase

  // Helper functions for SHA-256 hash computation

  // Function to perform right rotation
  function logic [31:0] rightrotate(input logic [31:0] x, input logic [7:0] r);
    rightrotate = (x >> r) | (x << (32 - r));  // Bitwise right rotate by r positions
  endfunction

  // Function to generate new wt value based on SHA-256 message schedule
  function logic [31:0] wtnew(input int i);
    logic [31:0] s0, s1;
    // Compute s0 and s1 using SHA-256 bitwise operations
    s0 = rightrotate(w[i][1], 7) ^ rightrotate(w[i][1], 18) ^ (w[i][1] >> 3);
    s1 = rightrotate(w[i][14], 17) ^ rightrotate(w[i][14], 19) ^ (w[i][14] >> 10);
    wtnew = w[i][0] + s0 + w[i][9] + s1;  // Compute wtnew for the given index
  endfunction

  // Function to perform one round of SHA-256 operation
  function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w, k);
    logic [31:0] S1, S0, ch, maj, t1, t2;  // Internal variables
    begin
      // Compute various intermediate values using SHA-256 bitwise operations
      S1        = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
      ch        = (e & f) ^ (~e & g);  // Choice function
      t1        = ch + S1 + h + k + w;  // Temporary value t1
      S0        = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
      maj       = (a & b) ^ (a & c) ^ (b & c);  // Majority function
      t2        = maj + S0;  // Temporary value t2
      sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};  // Update hash values
    end
  endfunction

  always_ff @(posedge clk, negedge reset_n) begin
    if (!reset_n) begin
      state <= IDLE;  // Reset state to IDLE when reset signal is active (low)
    end else begin
      case (state)
        IDLE: begin
          if (start) begin  // When the start signal is active, initialize variables
            mem_we <= 0;
            mem_addr <= message_addr;  // Set the memory address to the initial message address
            i <= 1;  // Initialize the loop counter
            t1 <= 0;  // Reset time step counters
            t2 <= 0;
            first <= 0;  // Reset 'first' and 'second' flags
            second <= 0;
            nonce <= 0;  // Initialize nonce counter

            // Initialize hash values for each nonce
            for (int j = 0; j < num_nonces; j++) begin
              h[j][0] <= 32'h6a09e667;
              h[j][1] <= 32'hbb67ae85;
              h[j][2] <= 32'h3c6ef372;
              h[j][3] <= 32'ha54ff53a;
              h[j][4] <= 32'h510e527f;
              h[j][5] <= 32'h9b05688c;
              h[j][6] <= 32'h1f83d9ab;
              h[j][7] <= 32'h5be0cd19;
            end

            state <= START;  // Move to START state to begin memory reading
          end else begin
            state <= IDLE;  // Stay in IDLE if start signal is not active
          end
        end
        START_BUFFER: begin
          // Buffer the start signal for memory read operation
          state <= START;  // Move to START state for memory read
        end
        START: begin
          if (!first) begin
            // First read, increment memory address and loop counter
            mem_addr <= message_addr + i;
            i <= i + 1;
            first <= 1;  // Set 'first' flag indicating first read is done

            state <= START;  // Stay in START state for next read
          end else begin
            // Second read, continue incrementing address and load data into w
            mem_addr <= message_addr + i;
            i <= i + 1;
            t2 <= t2 + 1;  // Increment t2 for loading into w array

            // Load memory data into w array for all nonces
            for (int j = 0; j < num_nonces; j++) begin
              w[j][t2] <= mem_read_data;
            end

            state <= READ;  // Move to READ state to continue memory reads
          end
        end
        READ: begin
          // Continue reading and loading into w array
          for (int j = 0; j < num_nonces; j++) begin
            w[j][t2] <= mem_read_data;
          end

          t2 <= t2 + 1;  // Increment time counter

          if (i > 20) begin
            // After 20 iterations, initialize w and h for all nonces
            for (int j = 0; j < num_nonces; j++) begin
              w[j][t2] <= mem_read_data;
              w[j][3]  <= j;  // Set unique value for w[j][3] (e.g., nonce index)
              for (int k = 4; k < 16; k++) begin
                if (k == 4) begin
                  w[j][k] <= 32'h80000000;  // Padding as per SHA-256 specification
                end else if (k == 15) begin
                  w[j][k] <= 32'd640;  // Length field as per SHA-256 specification
                end else begin
                  w[j][k] <= 32'h00000000;  // Zero fill for other words
                end
              end
              // Copy hash values to temporary registers
              wt[j] <= w[j][0];
              h0[j] <= h[j][0];
              h1[j] <= h[j][1];
              h2[j] <= h[j][2];
              h3[j] <= h[j][3];
              h4[j] <= h[j][4];
              h5[j] <= h[j][5];
              h6[j] <= h[j][6];
              h7[j] <= h[j][7];
            end
            t1 <= t1 + 1;  // Increment time counter
            second <= 1;  // Set second flag to indicate second phase of computation

            state <= COMPUTE;  // Move to COMPUTE state for processing
          end else if (t2 == 15) begin
            // If 16 words have been read, set up for hash computation
            for (int j = 0; j < num_nonces; j++) begin
              wt[j] <= w[j][0];  // Load first word of w into wt
              h0[j] <= h[j][0];  // Copy hash values to temporary registers
              h1[j] <= h[j][1];
              h2[j] <= h[j][2];
              h3[j] <= h[j][3];
              h4[j] <= h[j][4];
              h5[j] <= h[j][5];
              h6[j] <= h[j][6];
              h7[j] <= h[j][7];
            end
            t2 <= 0;  // Reset t2 counter
            t1 <= t1 + 1;  // Increment t1 for computation

            state <= COMPUTE;  // Move to COMPUTE state
          end else begin
            // Continue memory reads if fewer than 16 words are read
            mem_addr <= message_addr + i;
            i <= i + 1;

            state <= START;  // Go back to START to read more data
          end
        end
        FINISH: begin
          // Prepare w array for final block processing
          for (int j = 0; j < num_nonces; j++) begin
            for (int k = 8; k < 16; k++) begin
              if (k == 8) begin
                w[j][k] <= 32'h80000000;  // Padding start
              end else if (k == 15) begin
                w[j][k] <= 32'd256;  // Length field for SHA-256
              end else begin
                w[j][k] <= 32'h00000000;  // Zero fill
              end
            end
            wt[j] <= w[j][0];  // Initialize wt for SHA-256 computation
            h0[j] <= h[j][0];  // Copy hash values to temporary registers
            h1[j] <= h[j][1];
            h2[j] <= h[j][2];
            h3[j] <= h[j][3];
            h4[j] <= h[j][4];
            h5[j] <= h[j][5];
            h6[j] <= h[j][6];
            h7[j] <= h[j][7];
          end
          t1 <= t1 + 1;  // Increment time counter for computation

          state <= COMPUTE;  // Move to COMPUTE state for processing
        end
        COMPUTE: begin
          if (t1 <= 64) begin  // Loop through 64 rounds of SHA-256 operations
            for (int j = 0; j < num_nonces; j++) begin
              if (t1 < 16) begin
                wt[j] <= w[j][t1];  // Use preloaded words for first 16 rounds
              end else begin
                wt[j] <= wtnew(j);  // Calculate new words for remaining rounds
                for (int k = 0; k < 15; k++) begin
                  w[j][k] <= w[j][k+1];  // Shift w array left
                end
                w[j][15] <= wtnew(j);  // Store new word in w[15]
              end
              // Perform SHA-256 operations on current hash values
              {h0[j], h1[j], h2[j], h3[j], h4[j], h5[j], h6[j], h7[j]} <= sha256_op(
                  h0[j], h1[j], h2[j], h3[j], h4[j], h5[j], h6[j], h7[j], wt[j], k[t1-1]
              );
            end
            t1 <= t1 + 1;  // Increment time counter for next round

            state <= COMPUTE;  // Continue computing
          end else begin
            if (second) begin  // Check if this is the second computation phase
              // Finalize hash by adding initial hash values to computed values
              for (int j = 0; j < num_nonces; j++) begin
                w[j][0] <= h[j][0] + h0[j];
                w[j][1] <= h[j][1] + h1[j];
                w[j][2] <= h[j][2] + h2[j];
                w[j][3] <= h[j][3] + h3[j];
                w[j][4] <= h[j][4] + h4[j];
                w[j][5] <= h[j][5] + h5[j];
                w[j][6] <= h[j][6] + h6[j];
                w[j][7] <= h[j][7] + h7[j];

                // Reset hash values to initial state for next round
                h[j][0] <= 32'h6a09e667;
                h[j][1] <= 32'hbb67ae85;
                h[j][2] <= 32'h3c6ef372;
                h[j][3] <= 32'ha54ff53a;
                h[j][4] <= 32'h510e527f;
                h[j][5] <= 32'h9b05688c;
                h[j][6] <= 32'h1f83d9ab;
                h[j][7] <= 32'h5be0cd19;
              end
              t1 <= 0;  // Reset t1 counter
              second <= 0;  // Reset second flag

              state <= FINISH;  // Move to FINISH state for final block processing
            end else if (i <= 20) begin  // Check if more rounds are needed
              // Continue processing next set of data
              for (int j = 0; j < num_nonces; j++) begin
                h[j][0] <= h[j][0] + h0[j];
                h[j][1] <= h[j][1] + h1[j];
                h[j][2] <= h[j][2] + h2[j];
                h[j][3] <= h[j][3] + h3[j];
                h[j][4] <= h[j][4] + h4[j];
                h[j][5] <= h[j][5] + h5[j];
                h[j][6] <= h[j][6] + h6[j];
                h[j][7] <= h[j][7] + h7[j];
              end
              t1 <= 0;  // Reset t1 counter
              first <= 0;  // Reset first flag

              state <= START;  // Move back to START state for new block
            end else begin
              // Finalize computation by adding computed values to initial hash
              for (int j = 0; j < num_nonces; j++) begin
                h[j][0] <= h[j][0] + h0[j];
                h[j][1] <= h[j][1] + h1[j];
                h[j][2] <= h[j][2] + h2[j];
                h[j][3] <= h[j][3] + h3[j];
                h[j][4] <= h[j][4] + h4[j];
                h[j][5] <= h[j][5] + h5[j];
                h[j][6] <= h[j][6] + h6[j];
                h[j][7] <= h[j][7] + h7[j];
              end
              state <= WRITE;  // Move to WRITE state to write results to memory
            end
          end
        end
        WRITE_BUFFER: begin
          nonce <= nonce + 1;  // Increment nonce counter
          state <= WRITE;  // Move to WRITE state for writing to memory
        end
        WRITE: begin
          // Write final hash result to memory
          if (nonce <= num_nonces) begin
            mem_we <= 1;  // Enable memory write
            mem_addr <= output_addr + nonce;  // Set output address
            mem_write_data <= h[nonce][0];  // Write hash value
            second <= 1;  // Set second flag for next nonce
            state <= WRITE_BUFFER;  // Move to WRITE_BUFFER state
          end else begin
            done  <= 1;  // Signal completion
            state <= IDLE;  // Return to IDLE state
          end
        end
      endcase
    end
  end

endmodule
